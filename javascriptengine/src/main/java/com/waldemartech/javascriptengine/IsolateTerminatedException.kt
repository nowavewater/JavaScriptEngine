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
 * Exception produced when evaluation is terminated due to the [JavaScriptIsolate] being
 * closed or due to some crash.
 *
 *
 * Calling [JavaScriptIsolate.close] will cause this exception to be produced for all
 * previously requested but pending evaluations.
 *
 *
 * If an isolate has crashed (but not been closed), subsequently requested evaluations will fail
 * immediately with an IsolateTerminatedException (or a subclass) consistent with that
 * used for evaluations submitted before the crash.
 *
 *
 * Note that this exception will not be produced if the isolate has been explicitly closed before a
 * call to [JavaScriptIsolate.evaluateJavaScriptAsync], which will instead immediately
 * throw an IllegalStateException (and not asynchronously via a future). This applies even if the
 * isolate was closed following a crash.
 *
 *
 * Do not attempt to parse the information in this exception's message as it may change between
 * JavaScriptEngine versions.
 *
 *
 * Note that it is possible for an isolate to crash outside of submitted evaluations, in which
 * case an IsolateTerminatedException may not be observed. Consider instead using
 * [JavaScriptIsolate.addOnTerminatedCallback] if you need to reliably
 * or immediately detect isolate crashes rather than evaluation failures.
 */
open class IsolateTerminatedException : JavaScriptException {
    constructor() : super()
    constructor(message: String) : super(message)
}
