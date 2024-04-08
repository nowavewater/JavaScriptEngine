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
import android.os.ParcelFileDescriptor
import androidx.concurrent.futures.CallbackToFutureAdapter
import androidx.core.util.Consumer
import com.google.common.util.concurrent.ListenableFuture
import java.util.concurrent.Executor

/**
 * Covers the case where the environment is dead.
 *
 *
 * This state covers cases where the developer explicitly closes the sandbox or sandbox/isolate
 * being dead outside of the control of the developer.
 *
 *
 * Although being in this state is considered terminated from the app perspective, the service
 * side may still technically be running.
 */
internal class EnvironmentDeadState(private val mTerminationInfo: TerminationInfo) : IsolateState {
    override suspend fun evaluateJavaScriptAsync(code: String): String {
        return "environmentDeadFuture"
    }

    override fun evaluateJavaScriptAsync(afd: AssetFileDescriptor): ListenableFuture<String> {
        return environmentDeadFuture
    }

    override fun evaluateJavaScriptAsync(pfd: ParcelFileDescriptor): ListenableFuture<String> {
        return environmentDeadFuture
    }

    override fun setConsoleCallback(
        executor: Executor,
        callback: JavaScriptConsoleCallback
    ) {
    }

    override fun setConsoleCallback(callback: JavaScriptConsoleCallback) {}
    override fun clearConsoleCallback() {}
    override fun provideNamedData(name: String, inputBytes: ByteArray) {}
    override fun close() {}
    override fun canDie(): Boolean {
        return false
    }

    override fun addOnTerminatedCallback(
        executor: Executor,
        callback: Consumer<TerminationInfo>
    ) {
        executor.execute { callback.accept(mTerminationInfo) }
    }

    override fun removeOnTerminatedCallback(callback: Consumer<TerminationInfo>) {}
    private val environmentDeadFuture: ListenableFuture<String>
        private get() = CallbackToFutureAdapter.getFuture { completer: CallbackToFutureAdapter.Completer<String> ->
            val futureDebugMessage = "evaluateJavascript Future"
            completer.setException(mTerminationInfo.toJavaScriptException())
            futureDebugMessage
        }
}
