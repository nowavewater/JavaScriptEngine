/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.waldemartech.javascriptengine

import android.annotation.SuppressLint
import android.content.res.AssetFileDescriptor
import android.os.ParcelFileDescriptor
import android.os.RemoteException
import android.util.Log
import androidx.annotation.RequiresFeature
import androidx.core.util.Consumer
import com.google.common.util.concurrent.ListenableFuture
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.chromium.android_webview.js_sandbox.common.IJsSandboxIsolateClient
import java.util.Objects
import java.util.concurrent.Executor
import javax.annotation.concurrent.GuardedBy
import javax.annotation.concurrent.ThreadSafe

/**
 * Environment within a [JavaScriptSandbox] where JavaScript is executed.
 *
 *
 * A single [JavaScriptSandbox] process can contain any number of [JavaScriptIsolate]
 * instances where JS can be evaluated independently and in parallel.
 *
 *
 * Each isolate has its own state and JS global object,
 * and cannot interact with any other isolate through JS APIs. There is only a *moderate*
 * security boundary between isolates in a single [JavaScriptSandbox]. If the code in one
 * [JavaScriptIsolate] is able to compromise the security of the JS engine then it may be
 * able to observe or manipulate other isolates, since they run in the same process. For strong
 * isolation multiple [JavaScriptSandbox] processes should be used, but it is not supported
 * at the moment. Please find the feature request [here](https://crbug.com/1349860).
 *
 *
 * This class is thread-safe.
 */
@ThreadSafe
class JavaScriptIsolate private constructor(@JvmField val mJsSandbox: JavaScriptSandbox) : AutoCloseable {
    private val mLock = Any()
    private val mGuard = CloseGuardHelper.create()

    private val mutex = Mutex()

    @GuardedBy("mLock")
    private lateinit var mIsolateState: IsolateState

    private inner class JsSandboxIsolateClient internal constructor() :
        IJsSandboxIsolateClient.Stub() {
        override fun onTerminated(status: Int, message: String) {
            val identity = clearCallingIdentity()
            try {
                // If we're already closed, this will do nothing
                maybeSetIsolateDead(TerminationInfo(status, message))
            } finally {
                restoreCallingIdentity(identity)
            }
        }
    }

    init {
        synchronized(mLock) { mIsolateState = IsolateClosedState("isolate not initialized") }
    }

    // Create an isolate on the service side and complete initialization.
    // This is done outside of the constructor to avoid leaking a partially constructed
    // JavaScriptIsolate to the service (which would complicate thread-safety).
    @Throws(RemoteException::class)
    private fun initialize(settings: IsolateStartupParameters) {
        synchronized(mLock) {
            val instanceCallback: IJsSandboxIsolateClient?
            instanceCallback = if (mJsSandbox.isFeatureSupported(
                    JavaScriptSandbox.JS_FEATURE_ISOLATE_CLIENT
                )
            ) {
                JsSandboxIsolateClient()
            } else {
                null
            }
            val jsIsolateStub = mJsSandbox.createIsolateOnService(
                settings,
                instanceCallback
            )
            mIsolateState = IsolateUsableState(
                this, jsIsolateStub,
                settings.maxEvaluationReturnSizeBytes
            )
        }
    }

    /**
     * Changes the state to denote that the isolate is dead.
     *
     *
     * [IsolateClosedState] takes precedence so it will not change state if the current state
     * is [IsolateClosedState].
     *
     *
     * If the isolate is already dead, the existing dead state is preserved.
     *
     * @return true iff the state was changed to a new EnvironmentDeadState
     */
    fun maybeSetIsolateDead(terminationInfo: TerminationInfo): Boolean {
        synchronized(mLock) {
            if (terminationInfo.status == TerminationInfo.STATUS_MEMORY_LIMIT_EXCEEDED) {
                Log.e(TAG, "isolate exceeded its heap memory limit - killing sandbox")
                mJsSandbox.kill()
            }
            val oldState = mIsolateState
            if (oldState.canDie()) {
                mIsolateState = EnvironmentDeadState(terminationInfo)
                oldState.onDied(terminationInfo)
                return true
            }
        }
        return false
    }

    /**
     * Changes the state to denote that the sandbox is dead.
     *
     *
     * See [.maybeSetIsolateDead] for additional information.
     *
     * @return the generated termination info if it was set, or null if the state did not change
     */
    fun maybeSetSandboxDead(): TerminationInfo? {
        synchronized(mLock) {
            val terminationInfo =
                TerminationInfo(TerminationInfo.STATUS_SANDBOX_DEAD, "sandbox dead")
            return if (maybeSetIsolateDead(terminationInfo)) {
                terminationInfo
            } else {
                null
            }
        }
    }

    /**
     * Evaluates the given JavaScript code and returns the result.
     *
     *
     * There are 3 possible behaviors based on the output of the expression:
     *
     *  * **If the JS expression evaluates to a JS String**, then the Java Future
     * resolves to a Java String.
     *  * **If the JS expression evaluates to a JS Promise**,
     * and if [JavaScriptSandbox.isFeatureSupported] for
     * [JavaScriptSandbox.JS_FEATURE_PROMISE_RETURN] returns `true`, the Java Future
     * resolves to a Java String once the promise resolves. If it returns `false`, then the
     * Future resolves to an empty Java string.
     *  * **If the JS expression evaluates to another data type**, then the Java
     * Future resolves to an empty Java String.
     *
     * The environment uses a single JS global object for all the calls to
     * evaluateJavaScriptAsync(String) and [.provideNamedData] methods.
     * These calls are queued up and are run one at a time in sequence, using the single JS
     * environment for the isolate. The global variables set by one evaluation are visible for
     * later evaluations. This is similar to adding multiple `<script>` tags in HTML. The
     * behavior is also similar to
     * [android.webkit.WebView.evaluateJavascript].
     *
     *
     * If [JavaScriptSandbox.isFeatureSupported] for
     * [JavaScriptSandbox.JS_FEATURE_EVALUATE_WITHOUT_TRANSACTION_LIMIT] returns `false`,
     * the size of the expression to be evaluated and the result/error value is limited by the
     * binder transaction limit ([android.os.TransactionTooLargeException]). If it returns
     * `true`, they are not limited by the binder transaction limit but are bound by
     * [IsolateStartupParameters.setMaxEvaluationReturnSizeBytes] with a default size
     * of [IsolateStartupParameters.DEFAULT_MAX_EVALUATION_RETURN_SIZE_BYTES].
     *
     *
     * Do not use this method to transfer raw binary data. Scripts or results containing unpaired
     * surrogate code units are not supported.
     *
     * @param code JavaScript code to evaluate. The script should return a JavaScript String or,
     * alternatively, a Promise that will resolve to a String if
     * [JavaScriptSandbox.JS_FEATURE_PROMISE_RETURN] is supported.
     * @return a Future that evaluates to the result String of the evaluation or an exception (see
     * [JavaScriptException] and subclasses) if there is an error
     */
    suspend fun evaluateJavaScriptAsync(code: String): String {
        Objects.requireNonNull(code)
        mutex.withLock(mLock) {
            return mIsolateState.evaluateJavaScriptAsync(code)
        }
    }

    /**
     * Reads and evaluates the JavaScript code in the file described by the given
     * AssetFileDescriptor.
     *
     *
     * Please refer to the documentation of [.evaluateJavaScriptAsync] as the
     * behavior of this method is similar other than for the input type.
     *
     *
     * This API exposes the underlying file to the service. In case the service process is
     * compromised for unforeseen reasons, it might be able to read from the `AssetFileDescriptor` beyond the given length and offset.  This API does **not
     ** *  close the given `AssetFileDescriptor`.
     *
     *
     * **Note: The underlying file data must be UTF-8 encoded.**
     *
     *
     * This overload is useful when the source of the data is easily readable as an
     * `AssetFileDescriptor`, e.g. an asset or raw resource.
     *
     * @param afd an `AssetFileDescriptor` for a file containing UTF-8 encoded JavaScript
     * code to be evaluated
     * @return a Future that evaluates to the result String of the evaluation or an exception (see
     * [JavaScriptException] and subclasses) if there is an error
     */
    @RequiresFeature(
        name = JavaScriptSandbox.JS_FEATURE_EVALUATE_FROM_FD,
        enforcement = "androidx.javascriptengine.JavaScriptSandbox#isFeatureSupported"
    )
    fun evaluateJavaScriptAsync(afd: AssetFileDescriptor): ListenableFuture<String> {
        Objects.requireNonNull(afd)
        synchronized(mLock) { return mIsolateState.evaluateJavaScriptAsync(afd) }
    }

    /**
     * Reads and evaluates the JavaScript code in the file described by the given
     * `ParcelFileDescriptor`.
     *
     *
     * Please refer to the documentation of [.evaluateJavaScriptAsync] as the
     * behavior of this method is similar other than for the input type.
     *
     *
     * This API exposes the underlying file to the service. In case the service process is
     * compromised for unforeseen reasons, it might be able to read from the `ParcelFileDescriptor` beyond the given length and offset. This API does **not
     ** *  close the given `ParcelFileDescriptor`.
     *
     *
     * **Note: The underlying file data must be UTF-8 encoded.**
     *
     *
     * This overload is useful when the source of the data is easily readable as a
     * `ParcelFileDescriptor`, e.g. a file from shared memory or the app's data directory.
     *
     * @param pfd a `ParcelFileDescriptor` for a file containing UTF-8 encoded JavaScript
     * code that is evaluated
     * @return a Future that evaluates to the result String of the evaluation or an exception (see
     * [JavaScriptException] and subclasses) if there is an error
     */
    @RequiresFeature(
        name = JavaScriptSandbox.JS_FEATURE_EVALUATE_FROM_FD,
        enforcement = "androidx.javascriptengine.JavaScriptSandbox#isFeatureSupported"
    )
    fun evaluateJavaScriptAsync(pfd: ParcelFileDescriptor): ListenableFuture<String> {
        Objects.requireNonNull(pfd)
        synchronized(mLock) { return mIsolateState.evaluateJavaScriptAsync(pfd) }
    }

    /**
     * Closes the [JavaScriptIsolate] object and renders it unusable.
     *
     *
     * Once closed, no more method calls should be made. Pending evaluations will reject with
     * an [IsolateTerminatedException] immediately.
     *
     *
     * If [JavaScriptSandbox.isFeatureSupported] is `true` for [ ][JavaScriptSandbox.JS_FEATURE_ISOLATE_TERMINATION], then any pending evaluations are
     * terminated. If it is `false`, the isolate will not get cleaned
     * up until the pending evaluations have run to completion and will consume resources until
     * then.
     *
     *
     * Closing an isolate via this method does not wait on the isolate to clean up. Resources
     * held by the isolate may remain in use for a duration after this method returns.
     */
    override fun close() {
        closeWithDescription("isolate closed")
    }

    fun closeWithDescription(description: String) {
        synchronized(mLock) {
            mIsolateState.close()
            mIsolateState = IsolateClosedState(description)
        }
        // Do not hold mLock whilst calling into JavaScriptSandbox, as JavaScriptSandbox also has
        // its own lock and may want to call into JavaScriptIsolate from another thread.
        mJsSandbox.removeFromIsolateSet(this)
        mGuard.close()
    }

    /**
     * Provides a byte array for consumption from the JavaScript environment.
     *
     *
     * This method provides an efficient way to pass in data from Java into the JavaScript
     * environment which can be referred to from JavaScript. This is more efficient than including
     * data in the JS expression, and allows large data to be sent.
     *
     *
     * This data can be consumed in the JS environment using `android.consumeNamedDataAsArrayBuffer(String)` by referring to the data with the name that
     * was used when calling this method. This is a one-time transfer and the calls should be
     * paired.
     *
     *
     * A single name can only be used once in a particular [JavaScriptIsolate].
     * Clients can generate unique names for each call if they
     * need to use this method multiple times. The same name should be included into the JS code.
     *
     *
     * This API can be used to pass a WASM module into the JS
     * environment for compilation if [JavaScriptSandbox.isFeatureSupported] returns
     * `true` for [JavaScriptSandbox.JS_FEATURE_WASM_COMPILATION].
     * <br></br>
     * In Java,
     * <pre>
     * jsIsolate.provideNamedData("id-1", byteArray);
    </pre> *
     * In JS,
     * <pre>
     * android.consumeNamedDataAsArrayBuffer("id-1").then((value) => {
     * return WebAssembly.compile(value).then((module) => {
     * ...
     * });
     * });
    </pre> *
     *
     *
     * The environment uses a single JS global object for all the calls to [ ][.evaluateJavaScriptAsync] and provideNamedData(String, byte[]) methods.
     *
     *
     * This method should only be called if
     * [JavaScriptSandbox.isFeatureSupported]
     * returns true for [JavaScriptSandbox.JS_FEATURE_PROVIDE_CONSUME_ARRAY_BUFFER].
     *
     * @param name       identifier for the data that is passed. The same identifier should be used
     * in the JavaScript environment to refer to the data.
     * @param inputBytes bytes to be passed into the JavaScript environment. This array must not be
     * modified until the JavaScript promise returned by
     * consumeNamedDataAsArrayBuffer has resolved (or rejected).
     * @throws IllegalStateException if the name has previously been used in the isolate
     */
    @RequiresFeature(
        name = JavaScriptSandbox.JS_FEATURE_PROVIDE_CONSUME_ARRAY_BUFFER,
        enforcement = "androidx.javascriptengine.JavaScriptSandbox#isFeatureSupported"
    )
    fun provideNamedData(name: String, inputBytes: ByteArray) {
        Objects.requireNonNull(name)
        Objects.requireNonNull(inputBytes)
        synchronized(mLock) { mIsolateState.provideNamedData(name, inputBytes) }
    }

    @Throws(Throwable::class)  // super.finalize() throws Throwable
    protected fun finalize() {
        try {
            mGuard.warnIfOpen()
            close()
        } finally {
        //    super.finalize()
        }
    }

    /**
     * Set a JavaScriptConsoleCallback to process console messages from the isolate.
     *
     *
     * Scripts always have access to console APIs, regardless of whether a console callback is
     * set. By default, no console callback is set and calling a console API from JavaScript will do
     * nothing, and will be relatively cheap. Setting a console callback allows console messages to
     * be forwarded to the embedding application, but may negatively impact performance.
     *
     *
     * Note that console APIs may expose messages generated by both JavaScript code and
     * V8/JavaScriptEngine internals.
     *
     *
     * Use caution if using this in production code as it may result in the exposure of debugging
     * information or secrets through logs.
     *
     *
     * When setting a console callback, this method should be called before requesting any
     * evaluations. Calling setConsoleCallback after requesting evaluations may result in those
     * pending evaluations' console messages being dropped or logged to a previous console callback.
     *
     *
     * Note that delayed console messages may continue to be delivered after the isolate has been
     * closed (or has crashed).
     *
     * @param executor the executor for running callback methods
     * @param callback the callback implementing console logging behaviour
     */
    @RequiresFeature(
        name = JavaScriptSandbox.JS_FEATURE_CONSOLE_MESSAGING,
        enforcement = "androidx.javascriptengine.JavaScriptSandbox#isFeatureSupported"
    )
    fun setConsoleCallback(
        executor: Executor,
        callback: JavaScriptConsoleCallback
    ) {
        Objects.requireNonNull(executor)
        Objects.requireNonNull(callback)
        synchronized(mLock) { mIsolateState.setConsoleCallback(executor, callback) }
    }

    /**
     * Set a JavaScriptConsoleCallback to process console messages from the isolate.
     *
     *
     * This is the same as calling [.setConsoleCallback]
     * using the main executor of the context used to create the [JavaScriptSandbox] object.
     *
     * @param callback the callback implementing console logging behaviour
     */
    @RequiresFeature(
        name = JavaScriptSandbox.JS_FEATURE_CONSOLE_MESSAGING,
        enforcement = "androidx.javascriptengine.JavaScriptSandbox#isFeatureSupported"
    )
    fun setConsoleCallback(callback: JavaScriptConsoleCallback) {
        Objects.requireNonNull(callback)
        synchronized(mLock) {
            mIsolateState.setConsoleCallback(
                mJsSandbox.mainExecutor,
                callback
            )
        }
    }

    /**
     * Clear any JavaScriptConsoleCallback set via [.setConsoleCallback].
     *
     *
     * Clearing a callback is not guaranteed to take effect for any already pending evaluations.
     */
    @RequiresFeature(
        name = JavaScriptSandbox.JS_FEATURE_CONSOLE_MESSAGING,
        enforcement = "androidx.javascriptengine.JavaScriptSandbox#isFeatureSupported"
    )
    fun clearConsoleCallback() {
        synchronized(mLock) { mIsolateState.clearConsoleCallback() }
    }

    /**
     * Add a callback to listen for isolate crashes.
     *
     *
     * There is no guaranteed order to when these callbacks are triggered and unfinished
     * evaluations' futures are rejected.
     *
     *
     * Registering a callback after the isolate has crashed will result in it being executed
     * immediately on the supplied executor with the isolate's [TerminationInfo] as an
     * argument.
     *
     *
     * Closing an isolate via [.close] is not considered a crash, even if there are
     * unresolved evaluations, and will not trigger termination callbacks.
     *
     * @param executor the executor with which to run callback
     * @param callback the consumer to be called with TerminationInfo when a crash occurs
     * @throws IllegalStateException if the callback is already registered (using any executor)
     */
    @SuppressLint("RegistrationName")
    fun addOnTerminatedCallback(
        executor: Executor,
        callback: Consumer<TerminationInfo>
    ) {
        Objects.requireNonNull(executor)
        Objects.requireNonNull(callback)
        synchronized(mLock) { mIsolateState.addOnTerminatedCallback(executor, callback) }
    }

    /**
     * Add a callback to listen for isolate crashes.
     *
     *
     * This is the same as calling [.addOnTerminatedCallback] using the
     * main executor of the context used to create the [JavaScriptSandbox] object.
     *
     * @param callback the consumer to be called with TerminationInfo when a crash occurs
     * @throws IllegalStateException if the callback is already registered (using any executor)
     */
    @SuppressLint("RegistrationName")
    fun addOnTerminatedCallback(callback: Consumer<TerminationInfo>) {
        addOnTerminatedCallback(mJsSandbox.mainExecutor, callback)
    }

    /**
     * Remove a callback previously registered with addOnTerminatedCallback.
     *
     * @param callback the callback to unregister, if currently registered
     */
    @SuppressLint("RegistrationName")
    fun removeOnTerminatedCallback(callback: Consumer<TerminationInfo>) {
        Objects.requireNonNull(callback)
        synchronized(mLock) { mIsolateState.removeOnTerminatedCallback(callback) }
    }

    companion object {
        private const val TAG = "JavaScriptIsolate"
        @Throws(RemoteException::class)
        fun create(
            sandbox: JavaScriptSandbox,
            settings: IsolateStartupParameters
        ): JavaScriptIsolate {
            val isolate = JavaScriptIsolate(sandbox)
            isolate.initialize(settings)
            isolate.mGuard.open("close")
            return isolate
        }

        fun createDead(
            sandbox: JavaScriptSandbox,
            message: String
        ): JavaScriptIsolate {
            val isolate = JavaScriptIsolate(sandbox)
            val terminationInfo = TerminationInfo(TerminationInfo.STATUS_SANDBOX_DEAD, message)
            synchronized(isolate.mLock) {
                isolate.mIsolateState = EnvironmentDeadState(terminationInfo)
            }
            isolate.mGuard.open("close")
            return isolate
        }
    }
}
