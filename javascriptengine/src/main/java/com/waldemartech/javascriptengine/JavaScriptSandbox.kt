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

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.DeadObjectException
import android.os.IBinder
import android.os.RemoteException
import android.util.Log
import android.webkit.WebView
import androidx.annotation.RestrictTo
import androidx.annotation.StringDef
import androidx.annotation.VisibleForTesting
import androidx.concurrent.futures.CallbackToFutureAdapter
import androidx.core.content.ContextCompat
import androidx.core.content.pm.PackageInfoCompat
import com.google.common.util.concurrent.ListenableFuture
import com.waldemartech.javascriptengine.common.Utils
import kotlinx.coroutines.suspendCancellableCoroutine
import org.chromium.android_webview.js_sandbox.common.IJsSandboxIsolate
import org.chromium.android_webview.js_sandbox.common.IJsSandboxIsolateClient
import org.chromium.android_webview.js_sandbox.common.IJsSandboxService
import java.util.Objects
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.annotation.concurrent.GuardedBy
import javax.annotation.concurrent.ThreadSafe
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Sandbox that provides APIs for JavaScript evaluation in a restricted environment.
 *
 *
 * JavaScriptSandbox represents a connection to an isolated process. The isolated process is
 * exclusive to the calling app (i.e. it doesn't share anything with, and can't be compromised by
 * another app's isolated process).
 *
 *
 * Code that is run in a sandbox does not have any access to data
 * belonging to the original app unless explicitly passed into it by using the methods of this
 * class. This provides a security boundary between the calling app and the Javascript execution
 * environment.
 *
 *
 * The calling app can have only one isolated process at a time, so only one
 * instance of this class can be open at any given time.
 *
 *
 * It's safe to share a single [JavaScriptSandbox]
 * object with multiple threads and use it from multiple threads at once.
 * For example, [JavaScriptSandbox] can be stored at a global location and multiple threads
 * can create their own [JavaScriptIsolate] objects from it but the
 * [JavaScriptIsolate] object cannot be shared.
 */
@ThreadSafe
class JavaScriptSandbox internal constructor(
    private val mContext: Context, connectionSetup: ConnectionSetup,
    @field:GuardedBy("mLock") private val mJsSandboxService: IJsSandboxService
) : AutoCloseable {
    private val mLock = Any()
    private val mGuard = CloseGuardHelper.create()

    // Don't use mLock for the connection, allowing it to be severed at any time, regardless of
    // the status of the main mLock. Use an AtomicReference instead.
    //
    // The underlying ConnectionSetup is nullable, and is null iff the service has been unbound
    // (which should also imply dead or closed).
    private val mConnection: AtomicReference<ConnectionSetup?> = AtomicReference(connectionSetup)
    val features = mJsSandboxService.getSupportedFeatures()

    @GuardedBy("mLock")
    private var mActiveIsolateSet: MutableSet<JavaScriptIsolate> = HashSet()

    private enum class State {
        ALIVE,
        DEAD,
        CLOSED
    }

    @GuardedBy("mLock")
    private var mState: State = State.ALIVE
    @JvmField
    val mThreadPoolTaskExecutor = Executors.newCachedThreadPool(object : ThreadFactory {
        private val mCount = AtomicInteger(1)
        override fun newThread(r: Runnable): Thread {
            return Thread(r, "JavaScriptSandbox Thread #" + mCount.getAndIncrement())
        }
    })

    /**
     * A client-side feature, which may be conditional on one or more service-side features.
     */
    @RestrictTo(RestrictTo.Scope.LIBRARY)
    @StringDef(value = [JS_FEATURE_ISOLATE_TERMINATION, JS_FEATURE_PROMISE_RETURN, JS_FEATURE_PROVIDE_CONSUME_ARRAY_BUFFER, JS_FEATURE_WASM_COMPILATION, JS_FEATURE_ISOLATE_MAX_HEAP_SIZE, JS_FEATURE_EVALUATE_WITHOUT_TRANSACTION_LIMIT, JS_FEATURE_CONSOLE_MESSAGING, JS_FEATURE_ISOLATE_CLIENT, JS_FEATURE_EVALUATE_FROM_FD])
    @Retention(
        AnnotationRetention.SOURCE
    )
    @Target(
        AnnotationTarget.VALUE_PARAMETER,
        AnnotationTarget.FUNCTION,
        AnnotationTarget.PROPERTY_GETTER,
        AnnotationTarget.PROPERTY_SETTER
    )
    annotation class JsSandboxFeature

    // This set must not be modified after JavaScriptSandbox construction.
    private val mClientSideFeatureSet: HashSet<String> = buildClientSideFeatureSet(features)

    internal class ConnectionSetup(
        private val mContext: Context,
        continuation: Continuation<JavaScriptSandbox>
    ) : ServiceConnection {
        private var mContinuation: Continuation<JavaScriptSandbox>? = null
        private var mJsSandbox: JavaScriptSandbox? = null
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            // It's possible for the service to die and already have been restarted before
            // we've actually observed the original death (b/267864650). If that happens,
            // onServiceConnected will be called a second time immediately after
            // onServiceDisconnected even though we already unbound. Just do nothing.
            if (mContinuation == null) {
                return
            }
            val jsSandboxService = IJsSandboxService.Stub.asInterface(service)
            mJsSandbox = try {
                JavaScriptSandbox(mContext, this, jsSandboxService)
            } catch (e: DeadObjectException) {
                runShutdownTasks(e)
                return
            } catch (e: RemoteException) {
                runShutdownTasks(e)
                throw Utils.exceptionToRuntimeException(e)
            } catch (e: RuntimeException) {
                runShutdownTasks(e)
                throw Utils.exceptionToRuntimeException(e)
            }
            mJsSandbox?.let {
                mContinuation?.resume(it)
                mContinuation = null
            }

        }

        // TODO(crbug.com/1297672): We may want an explicit way to signal to the client that the
        // process crashed (like onRenderProcessGone in WebView), without them having to first call
        // one of the methods and have it fail.
        override fun onServiceDisconnected(name: ComponentName) {
            runShutdownTasks(
                RuntimeException(
                    "JavaScriptSandbox internal error: onServiceDisconnected()"
                )
            )
        }

        override fun onBindingDied(name: ComponentName) {
            runShutdownTasks(
                RuntimeException("JavaScriptSandbox internal error: onBindingDied()")
            )
        }

        override fun onNullBinding(name: ComponentName) {
            runShutdownTasks(
                RuntimeException("JavaScriptSandbox internal error: onNullBinding()")
            )
        }

        private fun runShutdownTasks(e: Exception) {
            if (mJsSandbox != null) {
                Log.e(TAG, "Sandbox has died", e)
                mJsSandbox!!.killImmediatelyOnThread()
            } else {
                mContext.unbindService(this)
                sIsReadyToConnect.set(true)
            }
            mContinuation?.resumeWithException(e)
            mContinuation = null
        }

        init {
            mContinuation = continuation
        }
    }

    // We prevent direct initializations of this class.
    // Use JavaScriptSandbox.createConnectedInstance().
    init {

        mGuard.open("close")
        // This should be at the end of the constructor.
    }
    /**
     * Creates and returns a [JavaScriptIsolate] within which JS can be executed with the
     * specified settings.
     *
     *
     * If the sandbox is dead, this will still return an isolate, but evaluations will fail with
     * [SandboxDeadException].
     *
     * @param settings the configuration for the isolate
     * @return a new JavaScriptIsolate
     */
    /**
     * Creates and returns a [JavaScriptIsolate] within which JS can be executed with default
     * settings.
     *
     * @return a new JavaScriptIsolate
     */
    @JvmOverloads
    fun createIsolate(settings: IsolateStartupParameters = IsolateStartupParameters()): JavaScriptIsolate {
        Objects.requireNonNull(settings)
        synchronized(mLock) {
            val isolate: JavaScriptIsolate = when (mState) {
                State.ALIVE -> try {
                    JavaScriptIsolate.create(this, settings)
                } catch (e: DeadObjectException) {
                    killDueToException(e)
                    JavaScriptIsolate.createDead(
                        this,
                        "sandbox found dead during call to createIsolate"
                    )
                } catch (e: RemoteException) {
                    killDueToException(e)
                    throw Utils.exceptionToRuntimeException(e)
                } catch (e: RuntimeException) {
                    killDueToException(e)
                    throw Utils.exceptionToRuntimeException(e)
                }

                State.DEAD -> JavaScriptIsolate.createDead(
                    this,
                    "sandbox was dead before call to createIsolate"
                )

                State.CLOSED -> throw IllegalStateException("Cannot create isolate in closed sandbox")
                else -> throw AssertionError("unreachable")
            }
            mActiveIsolateSet.add(isolate)
            return isolate
        }
    }

    // In practice, this method should only be called whilst already holding mLock, but it is
    // called via JavaScriptIsolate and this constraint cannot be cleanly expressed via GuardedBy.
    @Throws(RemoteException::class)
    fun createIsolateOnService(
        settings: IsolateStartupParameters,
        isolateInstanceCallback: IJsSandboxIsolateClient?
    ): IJsSandboxIsolate {
        synchronized(mLock) {
            assert(mState == State.ALIVE)
            return if (isFeatureSupported(JS_FEATURE_ISOLATE_CLIENT)) {
                mJsSandboxService.createIsolate2(
                    settings.maxHeapSizeBytes,
                    isolateInstanceCallback
                )
            } else if (isFeatureSupported(JS_FEATURE_ISOLATE_MAX_HEAP_SIZE)) {
                mJsSandboxService.createIsolateWithMaxHeapSizeBytes(
                    settings.maxHeapSizeBytes
                )
            } else {
                mJsSandboxService.createIsolate()
            }
        }
    }

    private fun buildClientSideFeatureSet(features: List<String>): HashSet<String> {
        val featureSet = HashSet<String>()
        if (features.contains(IJsSandboxService.ISOLATE_TERMINATION)) {
            featureSet.add(JS_FEATURE_ISOLATE_TERMINATION)
        }
        if (features.contains(IJsSandboxService.WASM_FROM_ARRAY_BUFFER)) {
            featureSet.add(JS_FEATURE_PROMISE_RETURN)
            featureSet.add(JS_FEATURE_PROVIDE_CONSUME_ARRAY_BUFFER)
            featureSet.add(JS_FEATURE_WASM_COMPILATION)
        }
        if (features.contains(IJsSandboxService.ISOLATE_MAX_HEAP_SIZE_LIMIT)) {
            featureSet.add(JS_FEATURE_ISOLATE_MAX_HEAP_SIZE)
        }
        if (features.contains(IJsSandboxService.EVALUATE_WITHOUT_TRANSACTION_LIMIT)) {
            featureSet.add(JS_FEATURE_EVALUATE_WITHOUT_TRANSACTION_LIMIT)
        }
        if (features.contains(IJsSandboxService.CONSOLE_MESSAGING)) {
            featureSet.add(JS_FEATURE_CONSOLE_MESSAGING)
        }
        if (features.contains(IJsSandboxService.ISOLATE_CLIENT)) {
            featureSet.add(JS_FEATURE_ISOLATE_CLIENT)
        }
        if (features.contains(IJsSandboxService.EVALUATE_FROM_FD)) {
            featureSet.add(JS_FEATURE_EVALUATE_FROM_FD)
        }
        return featureSet
    }

    /**
     * Checks whether a given feature is supported by the JS Sandbox implementation.
     *
     *
     * The sandbox implementation is provided by the version of WebView installed on the device.
     * The app must use this method to check which library features are supported by the device's
     * implementation before using them.
     *
     *
     * A feature check should be made prior to depending on certain features.
     *
     * @param feature the feature to be checked
     * @return `true` if supported, `false` otherwise
     */
    fun isFeatureSupported(@JsSandboxFeature feature: String): Boolean {
        Objects.requireNonNull(feature)
        return mClientSideFeatureSet.contains(feature)
    }

    fun removeFromIsolateSet(isolate: JavaScriptIsolate) {
        synchronized(mLock) { mActiveIsolateSet.remove(isolate) }
    }

    /**
     * Closes the [JavaScriptSandbox] object and renders it unusable.
     *
     *
     * The client is expected to call this method explicitly to terminate the isolated process.
     *
     *
     * Once closed, no more [JavaScriptSandbox] and [JavaScriptIsolate] method calls
     * can be made. Closing terminates the isolated process immediately. All pending evaluations are
     * immediately terminated. Once closed, the client may call
     * [JavaScriptSandbox.createConnectedInstanceAsync] to create another
     * [JavaScriptSandbox]. You should still call close even if the sandbox has died,
     * otherwise you will not be able to create a new one.
     */
    override fun close() {
        synchronized(mLock) {
            if (mState == State.CLOSED) {
                return
            }
            unbindService()
            sIsReadyToConnect.set(true)
            mState = State.CLOSED
        }
        notifyIsolatesAboutClosure()
        // This is the closest thing to a .close() method for ExecutorServices. This doesn't
        // force the threads or their Runnables to immediately terminate, but will ensure
        // that once the worker threads finish their current runnable (if any) that the thread
        // pool terminates them, preventing a leak of threads.
        mThreadPoolTaskExecutor.shutdownNow()
    }

    /**
     * Unbind the service if it hasn't been unbound already.
     *
     *
     * By itself, this will not put the sandbox into an official dead state, but any subsequent
     * interaction with the sandbox will result in a DeadObjectException. As this method does NOT
     * trigger ConnectionSetup.onServiceDisconnected or .onBindingDied, it is also useful for
     * testing how methods handle DeadObjectException without a race against these callbacks.
     *
     *
     * This will not, by itself, make JSE ready to create a new sandbox. The JavaScriptSandbox
     * object must still be explicitly closed.
     */
    @RestrictTo(RestrictTo.Scope.LIBRARY)
    @VisibleForTesting
    fun unbindService() {
        val connection = mConnection.getAndSet(null)
        if (connection != null) {
            mContext.unbindService(connection)
        }
    }

    /**
     * Kill the sandbox and immediately update state and trigger callbacks/futures on the calling
     * thread.
     *
     *
     * There is a risk of deadlock if this is called from an isolate-related callback. In order
     * to kill from code holding arbitrary locks, use [.kill] instead.
     */
    @RestrictTo(RestrictTo.Scope.LIBRARY)
    @VisibleForTesting
    fun killImmediatelyOnThread() {
        synchronized(mLock) {
            if (mState != State.ALIVE) {
                return
            }
            mState = State.DEAD
            unbindService()
        }
        notifyIsolatesAboutDeath()
    }

    /**
     * Kill the sandbox.
     *
     *
     * This will unbind the sandbox service so that any future IPC will fail immediately.
     * However, isolates will be notified asynchronously, from mContext's main executor.
     */
    fun kill() {
        unbindService()
        mainExecutor.execute { killImmediatelyOnThread() }
    }

    /**
     * Same as [.kill], but logs information about the cause.
     */
    fun killDueToException(e: Exception?) {
        if (e is DeadObjectException) {
            Log.e(TAG, "Sandbox died before or during during remote call", e)
        } else {
            Log.e(TAG, "Killing sandbox due to exception", e)
        }
        kill()
    }

    private fun notifyIsolatesAboutClosure() {
        // Do not hold mLock whilst calling into JavaScriptIsolate, as JavaScriptIsolate also has
        // its own lock and may want to call into JavaScriptSandbox from another thread.
        val activeIsolateSet: Set<JavaScriptIsolate>
        synchronized(mLock) {
            activeIsolateSet = mActiveIsolateSet
            mActiveIsolateSet = mutableSetOf()
        }
        for (isolate in activeIsolateSet) {
            val terminationInfo =
                TerminationInfo(TerminationInfo.STATUS_SANDBOX_DEAD, "sandbox closed")
            isolate.maybeSetIsolateDead(terminationInfo)
        }
    }

    private fun notifyIsolatesAboutDeath() {
        // Do not hold mLock whilst calling into JavaScriptIsolate, as JavaScriptIsolate also has
        // its own lock and may want to call into JavaScriptSandbox from another thread.
        val activeIsolateSet: Array<JavaScriptIsolate>
        synchronized(mLock) {
            activeIsolateSet = mActiveIsolateSet.toTypedArray<JavaScriptIsolate>()
        }
        for (isolate in activeIsolateSet) {
            isolate.maybeSetSandboxDead()
        }
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

    val mainExecutor: Executor
        get() = ContextCompat.getMainExecutor(mContext)

    companion object {
        private const val TAG = "JavaScriptSandbox"

        // TODO(crbug.com/1297672): Add capability to this class to support spawning
        // different processes as needed. This might require that we have a static
        // variable in here that tracks the existing services we are connected to and
        // connect to a different one when creating a new object.
        private const val JS_SANDBOX_SERVICE_NAME =
            "org.chromium.android_webview.js_sandbox.service.JsSandboxService0"
        val sIsReadyToConnect = AtomicBoolean(true)

        /**
         * Feature for [.isFeatureSupported].
         *
         *
         * When this
         * feature is present, [JavaScriptIsolate.close] terminates the currently running JS
         * evaluation and close the isolate. If it is absent, [JavaScriptIsolate.close] cannot
         * terminate any running or queued evaluations in the background, so the isolate continues to
         * consume resources until they complete.
         *
         *
         * Irrespective of this feature, calling [JavaScriptSandbox.close] terminates all
         * [JavaScriptIsolate] objects (and the isolated process) immediately and all pending
         * [JavaScriptIsolate.evaluateJavaScriptAsync] futures resolve with
         * [IsolateTerminatedException].
         */
        const val JS_FEATURE_ISOLATE_TERMINATION = "JS_FEATURE_ISOLATE_TERMINATION"

        /**
         * Feature for [.isFeatureSupported].
         *
         *
         * When this feature is present, JS expressions may return promises. The Future returned by
         * [JavaScriptIsolate.evaluateJavaScriptAsync] resolves to the promise's result,
         * once the promise resolves.
         */
        const val JS_FEATURE_PROMISE_RETURN = "JS_FEATURE_PROMISE_RETURN"

        /**
         * Feature for [.isFeatureSupported].
         * When this feature is present, [JavaScriptIsolate.provideNamedData]
         * can be used.
         *
         *
         * This also covers the JS API android.consumeNamedDataAsArrayBuffer(string).
         */
        const val JS_FEATURE_PROVIDE_CONSUME_ARRAY_BUFFER =
            "JS_FEATURE_PROVIDE_CONSUME_ARRAY_BUFFER"

        /**
         * Feature for [.isFeatureSupported].
         *
         *
         * This features provides additional behavior to [ ][JavaScriptIsolate.evaluateJavaScriptAsync] ()}. When this feature is present, the JS
         * API WebAssembly.compile(ArrayBuffer) can be used.
         */
        const val JS_FEATURE_WASM_COMPILATION = "JS_FEATURE_WASM_COMPILATION"

        /**
         * Feature for [.isFeatureSupported].
         *
         *
         * When this feature is present,
         * [JavaScriptSandbox.createIsolate] can be used.
         */
        const val JS_FEATURE_ISOLATE_MAX_HEAP_SIZE = "JS_FEATURE_ISOLATE_MAX_HEAP_SIZE"

        /**
         * Feature for [.isFeatureSupported].
         *
         *
         * When this feature is present, the script passed into
         * [JavaScriptIsolate.evaluateJavaScriptAsync] as well as the result/error is
         * not limited by the Binder transaction buffer size.
         */
        const val JS_FEATURE_EVALUATE_WITHOUT_TRANSACTION_LIMIT =
            "JS_FEATURE_EVALUATE_WITHOUT_TRANSACTION_LIMIT"

        /**
         * Feature for [.isFeatureSupported].
         *
         *
         * When this feature is present, [JavaScriptIsolate.setConsoleCallback] can be used to set
         * a [JavaScriptConsoleCallback] for processing console messages.
         */
        const val JS_FEATURE_CONSOLE_MESSAGING = "JS_FEATURE_CONSOLE_MESSAGING"

        /**
         * Feature for [.isFeatureSupported].
         *
         *
         * When this feature is present, the service can be provided with a Binder interface for
         * calling into the client, independent of callbacks.
         */
        const val JS_FEATURE_ISOLATE_CLIENT = "JS_FEATURE_ISOLATE_CLIENT"

        /**
         * Feature for [.isFeatureSupported].
         *
         *
         * When this feature is present,
         * [JavaScriptIsolate.evaluateJavaScriptAsync]
         * and [JavaScriptIsolate.evaluateJavaScriptAsync]
         * can be used to evaluate JavaScript code of known and unknown length from file descriptors.
         */
        const val JS_FEATURE_EVALUATE_FROM_FD = "JS_FEATURE_EVALUATE_FROM_FD"

        /**
         * Asynchronously create and connect to the sandbox process.
         *
         *
         * Only one sandbox process can exist at a time. Attempting to create a new instance before
         * the previous instance has been closed fails with an [IllegalStateException].
         *
         *
         * Sandbox support should be checked using [JavaScriptSandbox.isSupported] before
         * attempting to create a sandbox via this method.
         *
         * @param context the Context for the sandbox. Use an application context if the connection
         * is expected to outlive a single activity or service.
         * @return a Future that evaluates to a connected [JavaScriptSandbox] instance or an
         * exception if binding to service fails
         */
        suspend fun createConnectedInstanceAsync(
            context: Context
        ): JavaScriptSandbox {
            Objects.requireNonNull(context)
            val systemWebViewPackage = WebView.getCurrentWebViewPackage()
            // Technically, there could be a few race conditions before/after isSupport() where the
            // availability changes, which may result in a bind failure.
            if (systemWebViewPackage == null || !isSupported) {
                throw SandboxUnsupportedException("The system does not support JavaScriptSandbox")
            }
            val compName = ComponentName(systemWebViewPackage.packageName, JS_SANDBOX_SERVICE_NAME)
            val flag = Context.BIND_AUTO_CREATE or Context.BIND_EXTERNAL_SERVICE
            return bindToServiceWithSuspendable(context, compName, flag)
        }

        /**
         * Asynchronously create and connect to the sandbox process for testing.
         *
         *
         * Only one sandbox process can exist at a time. Attempting to create a new instance before
         * the previous instance has been closed will fail with an [IllegalStateException].
         *
         * @param context the Context for the sandbox. Use an application context if the connection
         * is expected to outlive a single activity or service.
         * @return a Future that evaluates to a connected [JavaScriptSandbox] instance or an
         * exception if binding to service fails
         */
        @VisibleForTesting
        @RestrictTo(RestrictTo.Scope.LIBRARY)
        suspend fun createConnectedInstanceForTestingAsync(
            context: Context
        ): JavaScriptSandbox {
            Objects.requireNonNull(context)
            val compName = ComponentName(context, JS_SANDBOX_SERVICE_NAME)
            val flag = Context.BIND_AUTO_CREATE
            return bindToServiceWithSuspendable(context, compName, flag)
        }

        val isSupported: Boolean
            /**
             * Check if JavaScriptSandbox is supported on the system.
             *
             *
             * This method should be used to check for sandbox support before calling
             * [JavaScriptSandbox.createConnectedInstanceAsync].
             *
             * @return true if JavaScriptSandbox is supported and false otherwise
             */
            get() {
                val systemWebViewPackage = WebView.getCurrentWebViewPackage() ?: return false
                val versionCode = PackageInfoCompat.getLongVersionCode(systemWebViewPackage)
                // The current IPC interface was introduced in 102.0.4976.0 (crrev.com/3560402), so all
                // versions above that are supported. Additionally, the relevant IPC changes were
                // cherry-picked into M101 at 101.0.4951.24 (crrev.com/3568575), so versions between
                // 101.0.4951.24 inclusive and 102.0.4952.0 exclusive are also supported.
                return versionCode >= 497600000L || 495102400L <= versionCode && versionCode < 495200000L
            }

        private suspend fun bindToServiceWithSuspendable(
            context: Context, compName: ComponentName, flag: Int
        ): JavaScriptSandbox {
            val intent = Intent()
            intent.setComponent(compName)
            return suspendCancellableCoroutine { continuation ->
                val connectionSetup = ConnectionSetup(context, continuation)
                if (sIsReadyToConnect.compareAndSet(true, false)) {
                    try {
                        val isBinding = context.bindService(intent, connectionSetup, flag)
                        if (isBinding) {
                            val mainExecutor: Executor = ContextCompat.getMainExecutor(context)
                            continuation.invokeOnCancellation {
                                context.unbindService(connectionSetup)
                            }
                        } else {
                            context.unbindService(connectionSetup)
                            sIsReadyToConnect.set(true)
                            continuation.resumeWithException(RuntimeException("bindService() returned false $intent"))
                        }
                    } catch (e: SecurityException) {
                        context.unbindService(connectionSetup)
                        sIsReadyToConnect.set(true)
                        continuation.resumeWithException(e)
                    }
                } else {
                    continuation.resumeWithException(IllegalStateException("Binding to already bound service"))
                }
            }
        }
    }
}
