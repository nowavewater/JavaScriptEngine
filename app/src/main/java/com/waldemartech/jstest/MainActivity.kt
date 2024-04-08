package com.waldemartech.jstest

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.lifecycleScope
import com.waldemartech.javascriptengine.JavaScriptSandbox
import com.waldemartech.jstest.ui.theme.JsTestTheme
import kotlinx.coroutines.guava.await
import kotlinx.coroutines.launch
import timber.log.Timber

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        testJs()

        setContent {
            JsTestTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    Greeting("Android")
                }
            }
        }
    }

    private fun testJs() {
        lifecycleScope.launch {
            Timber.i("step 1")
            val jsSandbox = JavaScriptSandbox.createConnectedInstanceAsync(applicationContext)
            Timber.i("step 2")
            val jsIsolate = jsSandbox.createIsolate()
            val code = "function sum(a, b) { let r = a + b; return r.toString(); }; sum(3, 4)"
            val result = jsIsolate.evaluateJavaScriptAsync(code)
            // Await the result
            Timber.i("result is $result")
            // Or add a callback
            /*Futures.addCallback<String>(
                resultFuture, object : FutureCallback<String?> {
                    override fun onSuccess(result: String?) {
                        textBox.text = result
                    }
                    override fun onFailure(t: Throwable) {
                        // Handle errors
                    }
                },
                mainExecutor
            )*/
        }
        /*val jsSandboxFuture: ListenableFuture<JavaScriptSandbox> =
            JavaScriptSandbox.createConnectedInstanceAsync(this)
        val jsIsolate: JavaScriptIsolate = jsSandboxFuture.get().createIsolate()
        Timber.i("execute step one")
        val code = "function sum(a, b) { let r = a + b; return r.toString(); }; sum(3, 4)"
        val resultFuture: ListenableFuture<String> = jsIsolate.evaluateJavaScriptAsync(code)
        Timber.i("execute step two")
        val result: String = resultFuture.get(5, TimeUnit.SECONDS)
        Timber.i("execute step three")
        Timber.i("execute sum result $result")*/
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    JsTestTheme {
        Greeting("Android")
    }
}