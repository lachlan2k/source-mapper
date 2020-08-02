package burp.lib.checks

import burp.IHttpRequestResponse
import burp.IScanIssue
import burp.IScannerCheck
import burp.IScannerInsertionPoint
import burp.SourceMapperController
import burp.lib.SourceMapExtractor
import burp.lib.issues.SourceMapFoundIssue

class AnalyseMapFileCheck(private val controller: SourceMapperController) : IScannerCheck {
    override fun consolidateDuplicateIssues(existingIssue: IScanIssue?, newIssue: IScanIssue?) =
        when (existingIssue?.issueDetail) {
            null -> 0
            newIssue?.issueDetail -> -1
            else -> 0
        }

    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse?): MutableList<IScanIssue> {
        if (baseRequestResponse == null) return ArrayList()

        val requestInfo = controller.helpers.analyzeRequest(baseRequestResponse)
        val isMapExt = requestInfo.url.file.endsWith(".js.map", true)

        if (!isMapExt) {
            return ArrayList()
        }

        val responseInfo = controller.helpers.analyzeResponse(baseRequestResponse.response)

        val responseStr = controller.helpers.bytesToString(baseRequestResponse.response)
        val responseBody = responseStr.substring(responseInfo.bodyOffset)

        return try {
            val extractor = SourceMapExtractor(responseBody)

            val filenames = extractor.filenames
            val files = extractor.files

            controller.store.insert(requestInfo.url, files)

            arrayListOf(SourceMapFoundIssue(requestInfo.url, emptyArray(), baseRequestResponse.httpService, filenames))
        } catch (e: SourceMapExtractor.InvalidSourceMapException) {
            ArrayList()
        }
    }

    override fun doActiveScan(baseRequestResponse: IHttpRequestResponse?, insertionPoint: IScannerInsertionPoint?): MutableList<IScanIssue> = ArrayList()
}