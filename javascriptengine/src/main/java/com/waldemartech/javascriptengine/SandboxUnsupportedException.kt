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

/**
 * Exception thrown when attempting to create a [JavaScriptSandbox] via
 * [JavaScriptSandbox.createConnectedInstanceAsync] when doing so is
 * not supported.
 *
 *
 * This can occur when the WebView package is too old to provide a sandbox implementation.
 */
class SandboxUnsupportedException(error: String) : RuntimeException(error)
