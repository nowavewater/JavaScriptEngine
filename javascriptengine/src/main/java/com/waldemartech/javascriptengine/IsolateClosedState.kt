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
import androidx.core.util.Consumer
import com.google.common.util.concurrent.ListenableFuture
import java.util.concurrent.Executor

/**
 * Covers cases where the isolate is explicitly closed or uninitialized.
 *
 *
 * Although being in this state is considered terminated from the app perspective, the service
 * side may still technically be running.
 */
internal class IsolateClosedState(private val mDescription: String) : IsolateState {
    override suspend fun evaluateJavaScriptAsync(code: String): String {
        throw IllegalStateException(
            "Calling evaluateJavaScriptAsync() when $mDescription"
        )
    }

    override fun evaluateJavaScriptAsync(afd: AssetFileDescriptor): ListenableFuture<String> {
        throw IllegalStateException(
            "Calling evaluateJavaScriptAsync() when $mDescription"
        )
    }

    override fun evaluateJavaScriptAsync(pfd: ParcelFileDescriptor): ListenableFuture<String> {
        throw IllegalStateException(
            "Calling evaluateJavaScriptAsync() when $mDescription"
        )
    }

    override fun setConsoleCallback(
        executor: Executor,
        callback: JavaScriptConsoleCallback
    ) {
        throw IllegalStateException(
            "Calling setConsoleCallback() when $mDescription"
        )
    }

    override fun setConsoleCallback(callback: JavaScriptConsoleCallback) {
        throw IllegalStateException(
            "Calling setConsoleCallback() when $mDescription"
        )
    }

    override fun clearConsoleCallback() {
        throw IllegalStateException(
            "Calling clearConsoleCallback() when $mDescription"
        )
    }

    override fun provideNamedData(name: String, inputBytes: ByteArray) {
        throw IllegalStateException(
            "Calling provideNamedData() when $mDescription"
        )
    }

    override fun close() {}
    override fun canDie(): Boolean {
        return false
    }

    override fun addOnTerminatedCallback(
        executor: Executor,
        callback: Consumer<TerminationInfo>
    ) {
        throw IllegalStateException(
            "Calling addOnTerminatedCallback() when $mDescription"
        )
    }

    override fun removeOnTerminatedCallback(callback: Consumer<TerminationInfo>) {
        throw IllegalStateException(
            "Calling removeOnTerminatedCallback() when $mDescription"
        )
    }
}
