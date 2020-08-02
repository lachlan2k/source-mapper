package burp

import java.io.PrintStream

class BurpExtender : IBurpExtender {
    lateinit var controller: SourceMapperController

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        System.setOut(PrintStream(callbacks.stdout))
        System.setErr(PrintStream(callbacks.stderr))

        callbacks.setExtensionName("SourceMapperKt")
        controller = SourceMapperController(callbacks)
    }
}