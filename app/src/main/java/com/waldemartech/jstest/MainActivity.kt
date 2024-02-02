package com.waldemartech.jstest

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.google.common.util.concurrent.ListenableFuture
import com.waldemartech.javascriptengine.JavaScriptIsolate
import com.waldemartech.javascriptengine.JavaScriptSandbox
import com.waldemartech.jstest.ui.theme.JsTestTheme
import java.util.concurrent.TimeUnit


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
        val jsSandboxFuture: ListenableFuture<JavaScriptSandbox> =
            JavaScriptSandbox.createConnectedInstanceAsync(this)



        val jsIsolate: JavaScriptIsolate = jsSandboxFuture.get().createIsolate()


        val code = "function sum(a, b) { let r = a + b; return r.toString(); }; sum(3, 4)"
        val resultFuture: ListenableFuture<String> = jsIsolate.evaluateJavaScriptAsync(code)
        val result: String = resultFuture.get(5, TimeUnit.SECONDS)
        Log.i("MainActivity", result)
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