/*
 * Copyright 2023 The Android Open Source Project
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

import android.content.res.AssetFileDescriptor
import android.os.DeadObjectException
import android.os.ParcelFileDescriptor
import android.os.RemoteException
import android.util.Log
import androidx.concurrent.futures.CallbackToFutureAdapter
import androidx.core.util.Consumer
import com.google.common.util.concurrent.ListenableFuture
import com.waldemartech.javascriptengine.common.LengthLimitExceededException
import com.waldemartech.javascriptengine.common.Utils
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.suspendCancellableCoroutine
import org.chromium.android_webview.js_sandbox.common.IJsSandboxConsoleCallback
import org.chromium.android_webview.js_sandbox.common.IJsSandboxIsolate
import org.chromium.android_webview.js_sandbox.common.IJsSandboxIsolateCallback
import org.chromium.android_webview.js_sandbox.common.IJsSandboxIsolateSyncCallback
import java.io.IOException
import java.io.UncheckedIOException
import java.nio.charset.StandardCharsets
import java.util.Objects
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import javax.annotation.concurrent.GuardedBy
import javax.annotation.concurrent.NotThreadSafe
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Covers the case where the isolate is functional.
 */
@OptIn(InternalCoroutinesApi::class)
@NotThreadSafe
internal class IsolateUsableState(
    val mJsIsolate: JavaScriptIsolate,
    /**
     * Interface to underlying service-backed implementation.
     */
    private val mJsIsolateStub: IJsSandboxIsolate,
    val mMaxEvaluationReturnSizeBytes: Int
) : IsolateState {
    private val mLock = Any()

    @GuardedBy("mLock")
    private var mPendingCompleterSet: MutableSet<Continuation<String>> = HashSet()

    // mOnTerminatedCallbacks does not require this.mLock, as all accesses should be performed
    // whilst holding the mLock of the JavaScriptIsolate that owns this state object.
    private val mOnTerminatedCallbacks = HashMap<Consumer<TerminationInfo>, Executor?>()

    private inner class IJsSandboxIsolateSyncCallbackStubWrapper internal constructor(
        private val mContinuation: Continuation<String>
    ) : IJsSandboxIsolateSyncCallback.Stub() {
        override fun reportResultWithFd(afd: AssetFileDescriptor) {
            Objects.requireNonNull(afd)
            // The completer needs to be removed before offloading to the executor, otherwise there
            // is a race to complete it if all evaluations are cancelled.
            removePending(mContinuation)
            mJsIsolate.mJsSandbox.mThreadPoolTaskExecutor.execute {
                val result: String = try {
                    Utils.readToString(
                        afd,
                        mMaxEvaluationReturnSizeBytes,  /*truncate=*/
                        false
                    )
                } catch (ex: IOException) {
                    mContinuation.resumeWithException(
                        JavaScriptException(
                            "Retrieving result failed: " + ex.message
                        )
                    )
                    return@execute
                } catch (ex: UnsupportedOperationException) {
                    mContinuation.resumeWithException(
                        JavaScriptException(
                            "Retrieving result failed: " + ex.message
                        )
                    )
                    return@execute
                } catch (ex: LengthLimitExceededException) {
                    if (ex.message != null) {
                        mContinuation.resumeWithException(
                            EvaluationResultSizeLimitExceededException(
                                ex.message!!
                            )
                        )
                    } else {
                        mContinuation.resumeWithException(
                            EvaluationResultSizeLimitExceededException()
                        )
                    }
                    return@execute
                }
                handleEvaluationResult(mContinuation, result)
            }
        }

        override fun reportErrorWithFd(@ExecutionErrorTypes type: Int, afd: AssetFileDescriptor) {
            Objects.requireNonNull(afd)
            // The completer needs to be removed before offloading to the executor, otherwise there
            // is a race to complete it if all evaluations are cancelled.
            removePending(mContinuation)
            mJsIsolate.mJsSandbox.mThreadPoolTaskExecutor.execute {
                val error: String
                error = try {
                    Utils.readToString(
                        afd,
                        mMaxEvaluationReturnSizeBytes,  /*truncate=*/
                        true
                    )
                } catch (ex: IOException) {
                    mContinuation.resumeWithException(
                        JavaScriptException(
                            "Retrieving error failed: " + ex.message
                        )
                    )
                    return@execute
                } catch (ex: UnsupportedOperationException) {
                    mContinuation.resumeWithException(
                        JavaScriptException(
                            "Retrieving error failed: " + ex.message
                        )
                    )
                    return@execute
                } catch (ex: LengthLimitExceededException) {
                    throw AssertionError("unreachable")
                }
                handleEvaluationError(mContinuation, type, error)
            }
        }
    }

    private inner class IJsSandboxIsolateCallbackStubWrapper internal constructor(
        private val mContinuation: Continuation<String>
    ) : IJsSandboxIsolateCallback.Stub() {
        override fun reportResult(result: String) {
            Objects.requireNonNull(result)
            removePending(mContinuation)
            val identityToken = clearCallingIdentity()
            try {
                handleEvaluationResult(mContinuation, result)
            } finally {
                restoreCallingIdentity(identityToken)
            }
        }

        override fun reportError(@ExecutionErrorTypes type: Int, error: String) {
            Objects.requireNonNull(error)
            removePending(mContinuation)
            val identityToken = clearCallingIdentity()
            try {
                handleEvaluationError(mContinuation, type, error)
            } finally {
                restoreCallingIdentity(identityToken)
            }
        }
    }

    internal class JsSandboxConsoleCallbackRelay(
        private val mExecutor: Executor,
        private val mCallback: JavaScriptConsoleCallback
    ) : IJsSandboxConsoleCallback.Stub() {
        override fun consoleMessage(
            contextGroupId: Int, level: Int, message: String,
            source: String, line: Int, column: Int, trace: String
        ) {
            val identity = clearCallingIdentity()
            try {
                mExecutor.execute {
                    require(
                        !(level and JavaScriptConsoleCallback.ConsoleMessage.LEVEL_ALL == 0
                                || level - 1 and level != 0)
                    ) { "invalid console level $level provided by isolate" }
                    Objects.requireNonNull(message)
                    Objects.requireNonNull(source)
                    mCallback.onConsoleMessage(
                        JavaScriptConsoleCallback.ConsoleMessage(
                            level, message, source, line, column, trace
                        )
                    )
                }
            } catch (e: RejectedExecutionException) {
                Log.e(TAG, "Console message dropped", e)
            } finally {
                restoreCallingIdentity(identity)
            }
        }

        override fun consoleClear(contextGroupId: Int) {
            val identity = clearCallingIdentity()
            try {
                mExecutor.execute { mCallback.onConsoleClear() }
            } catch (e: RejectedExecutionException) {
                Log.e(TAG, "Console clear dropped", e)
            } finally {
                restoreCallingIdentity(identity)
            }
        }
    }

    override suspend fun evaluateJavaScriptAsync(code: String): String {
        if (mJsIsolate.mJsSandbox.isFeatureSupported(
                JavaScriptSandbox.JS_FEATURE_EVALUATE_WITHOUT_TRANSACTION_LIMIT
            )
        ) {
            // This process can be made more memory efficient by converting the
            // String to UTF-8 encoded bytes and writing to the pipe in chunks.
            val inputBytes = code.toByteArray(StandardCharsets.UTF_8)
            return evaluateJavaScriptAsync(inputBytes)
        }

        return suspendCancellableCoroutine { continuation ->
            val futureDebugMessage = "evaluateJavascript Future"
            val callbackStub = IJsSandboxIsolateCallbackStubWrapper(continuation)
            try {
                mJsIsolateStub.evaluateJavascript(code, callbackStub)
                addPending(continuation)
            } catch (e: DeadObjectException) {
                val terminationInfo = killSandbox(e)
                continuation.tryResumeWithException(terminationInfo.toJavaScriptException())
            } catch (e: RemoteException) {
                throw killSandboxAndGetRuntimeException(e)
            } catch (e: RuntimeException) {
                throw killSandboxAndGetRuntimeException(e)
            }
            futureDebugMessage
        }
    }

    override fun evaluateJavaScriptAsync(afd: AssetFileDescriptor): ListenableFuture<String> {
        return CallbackToFutureAdapter.getFuture { completer: CallbackToFutureAdapter.Completer<String> ->
            val futureDebugMessage = "evaluateJavascript Future"
            /*val callbackStub = IJsSandboxIsolateSyncCallbackStubWrapper(completer)
            try {
                mJsIsolateStub.evaluateJavascriptWithFd(afd, callbackStub)
                addPending(completer)
            } catch (e: DeadObjectException) {
                val terminationInfo = killSandbox(e)
                completer.setException(terminationInfo.toJavaScriptException())
            } catch (e: RemoteException) {
                throw killSandboxAndGetRuntimeException(e)
            } catch (e: RuntimeException) {
                throw killSandboxAndGetRuntimeException(e)
            }*/
            futureDebugMessage
        }
    }

    override fun evaluateJavaScriptAsync(pfd: ParcelFileDescriptor): ListenableFuture<String> {
        val length = if (pfd.statSize >= 0) pfd.statSize else AssetFileDescriptor.UNKNOWN_LENGTH
        val wrapperAfd = AssetFileDescriptor(pfd, 0, length)
        return evaluateJavaScriptAsync(wrapperAfd)
    }

    override fun setConsoleCallback(
        executor: Executor,
        callback: JavaScriptConsoleCallback
    ) {
        try {
            mJsIsolateStub.setConsoleCallback(
                JsSandboxConsoleCallbackRelay(executor, callback)
            )
        } catch (e: DeadObjectException) {
            killSandbox(e)
        } catch (e: RemoteException) {
            throw killSandboxAndGetRuntimeException(e)
        } catch (e: RuntimeException) {
            throw killSandboxAndGetRuntimeException(e)
        }
    }

    override fun setConsoleCallback(callback: JavaScriptConsoleCallback) {
        setConsoleCallback(mJsIsolate.mJsSandbox.mainExecutor, callback)
    }

    override fun clearConsoleCallback() {
        try {
            mJsIsolateStub.setConsoleCallback(null)
        } catch (e: DeadObjectException) {
            killSandbox(e)
        } catch (e: RemoteException) {
            throw killSandboxAndGetRuntimeException(e)
        } catch (e: RuntimeException) {
            throw killSandboxAndGetRuntimeException(e)
        }
    }

    override fun provideNamedData(name: String, inputBytes: ByteArray) {
        // We pass the codeAfd to the separate sandbox process but we still need to close
        // it on our end to avoid file descriptor leaks.
        try {
            Utils.writeBytesIntoPipeAsync(
                inputBytes,
                mJsIsolate.mJsSandbox.mThreadPoolTaskExecutor
            ).use { codeAfd ->
                try {
                    val success = mJsIsolateStub.provideNamedData(name, codeAfd)
                    if (!success) {
                        throw IllegalStateException(
                            "Data with name '$name' has already been provided"
                        )
                    } else {

                    }
                } catch (e: DeadObjectException) {
                    killSandbox(e)
                } catch (e: RemoteException) {
                    throw killSandboxAndGetRuntimeException(e)
                } catch (e: RuntimeException) {
                    throw killSandboxAndGetRuntimeException(e)
                }
            }
        } catch (e: IOException) {
            throw UncheckedIOException(e)
        }
    }

    override fun close() {
        try {
            mJsIsolateStub.close()
        } catch (e: DeadObjectException) {
            killSandbox(e)
        } catch (e: RemoteException) {
            Log.e(TAG, "Exception was thrown during close()", e)
            killSandbox(e)
        } catch (e: RuntimeException) {
            Log.e(TAG, "Exception was thrown during close()", e)
            killSandbox(e)
        }
        cancelAllPendingEvaluations(IsolateTerminatedException("isolate closed"))
    }

    override fun canDie(): Boolean {
        return true
    }

    override fun onDied(terminationInfo: TerminationInfo) {
        cancelAllPendingEvaluations(terminationInfo.toJavaScriptException())
        mOnTerminatedCallbacks.forEach { (callback: Consumer<TerminationInfo>, executor: Executor?) ->
            executor!!.execute {
                callback.accept(
                    terminationInfo
                )
            }
        }
    }

    // Caller should call mJsIsolate.removePending(mCompleter) first
    fun handleEvaluationError(
        continuation: Continuation<String>,
        type: Int, error: String
    ) {
        when (type) {
            IJsSandboxIsolateSyncCallback.JS_EVALUATION_ERROR -> continuation.resumeWithException(
                EvaluationFailedException(error)
            )

            IJsSandboxIsolateSyncCallback.MEMORY_LIMIT_EXCEEDED -> {
                // Note that we won't ever receive a MEMORY_LIMIT_EXCEEDED evaluation error if
                // the service side supports termination notifications, so this only handles the
                // case where it doesn't.
                val terminationInfo =
                    TerminationInfo(TerminationInfo.STATUS_MEMORY_LIMIT_EXCEEDED, error)
                mJsIsolate.maybeSetIsolateDead(terminationInfo)
                // The completer was already removed from the set, so we're responsible for it.
                // Use our exception even if the isolate was already dead or closed. This might
                // result in an exception which is inconsistent with everything else if there was
                // a death or close before we called maybeSetIsolateDead above, but that requires
                // the app to have already set up a race condition.
                continuation.resumeWithException(terminationInfo.toJavaScriptException())
            }

            IJsSandboxIsolateSyncCallback.FILE_DESCRIPTOR_IO_ERROR -> continuation.resumeWithException(
                DataInputException(error)
            )

            else -> continuation.resumeWithException(
                JavaScriptException(
                    "Unknown error: code $type: $error"
                )
            )
        }
    }

    // Caller should call mJsIsolate.removePending(mCompleter) first
    fun handleEvaluationResult(
        continuation: Continuation<String>,
        result: String
    ) {
        continuation.resume(result)
    }

    fun removePending(continuation: Continuation<String>): Boolean {
        synchronized(mLock) { return mPendingCompleterSet.remove(continuation) }
    }

    fun addPending(continuation: Continuation<String>) {
        synchronized(mLock) { mPendingCompleterSet.add(continuation) }
    }

    // Cancel all pending and future evaluations with the given exception.
    // Only the first call to this method has any effect.
    fun cancelAllPendingEvaluations(e: Exception) {
        var continuations: Set<Continuation<String>>
        synchronized(mLock) {
            continuations = mPendingCompleterSet
            mPendingCompleterSet = mutableSetOf()
        }
        for (ele in continuations) {
            ele.resumeWithException(e)
        }
    }

    suspend fun evaluateJavaScriptAsync(code: ByteArray): String {
        return suspendCancellableCoroutine { contination ->
            val futureDebugMessage = "evaluateJavascript Future"
            val callbackStub = IJsSandboxIsolateSyncCallbackStubWrapper(contination)
            try {
                Utils.writeBytesIntoPipeAsync(
                    code,
                    mJsIsolate.mJsSandbox.mThreadPoolTaskExecutor
                ).use { codeAfd ->
                    // We pass the codeAfd to the separate sandbox process but we still need to
                    // close it on our end to avoid file descriptor leaks.
                    try {
                        mJsIsolateStub.evaluateJavascriptWithFd(
                            codeAfd,
                            callbackStub
                        )
                    } catch (e: DeadObjectException) {
                        val terminationInfo = killSandbox(e)
                        contination.tryResumeWithException(terminationInfo.toJavaScriptException())
                    } catch (e: RemoteException) {
                        throw killSandboxAndGetRuntimeException(e)
                    } catch (e: RuntimeException) {
                        throw killSandboxAndGetRuntimeException(e)
                    }
                    addPending(contination)
                }
            } catch (e: IOException) {
                throw UncheckedIOException(e)
            }
            futureDebugMessage
        }
    }

    override fun addOnTerminatedCallback(
        executor: Executor,
        callback: Consumer<TerminationInfo>
    ) {
        check(
            mOnTerminatedCallbacks.putIfAbsent(
                callback,
                executor
            ) == null
        ) { "Termination callback already registered" }
    }

    override fun removeOnTerminatedCallback(callback: Consumer<TerminationInfo>) {
        synchronized(mLock) { mOnTerminatedCallbacks.remove(callback) }
    }

    /**
     * Kill the sandbox and update state.
     * @param e the exception causing us to kill the sandbox
     * @return terminationInfo that has been set on the isolate
     */
    private fun killSandbox(e: Exception): TerminationInfo {
        mJsIsolate.mJsSandbox.killDueToException(e)
        val terminationInfo = mJsIsolate.maybeSetSandboxDead()
        // We're in the Usable state and the call stack should be holding a lock on the isolate,
        // so this should be the first time we find out the sandbox/isolate has died and
        // terminationInfo should never be null here.
        Objects.requireNonNull(terminationInfo)
        return terminationInfo!!
    }

    /**
     * Kill the sandbox, update state, and return a RuntimeException.
     * @param e the original exception causing us to kill the sandbox
     * @return a runtime exception which may optionally be thrown
     */
    private fun killSandboxAndGetRuntimeException(e: Exception): RuntimeException {
        killSandbox(e)
        return Utils.exceptionToRuntimeException(e)
    }

    companion object {
        private const val TAG = "IsolateUsableState"
    }
}
