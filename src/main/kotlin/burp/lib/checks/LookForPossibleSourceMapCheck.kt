package burp.lib.checks

import burp.IHttpRequestResponse
import burp.IScanIssue
import burp.IScannerCheck
import burp.IScannerInsertionPoint
import burp.SourceMapperController
import burp.lib.issues.PossibleSourceMapIssue

class LookForPossibleSourceMapCheck(private val controller: SourceMapperController) : IScannerCheck {
    private val sourceMapCommentPattern = """//#\s?sourceMappingURL=(.+?)(?=\\n|\n|$|//)""".toRegex()

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue?, newIssue: IScanIssue?) =
        when (existingIssue?.issueDetail) {
            null -> 0
            newIssue?.issueDetail -> -1
            else -> 0
        }

    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse?): MutableList<IScanIssue> {
        if (baseRequestResponse == null) return ArrayList()

        println("Doing passive scan")

        val requestInfo = controller.helpers.analyzeRequest(baseRequestResponse)
        val responseInfo = controller.helpers.analyzeResponse(baseRequestResponse.response)

        val responseStr = controller.helpers.bytesToString(baseRequestResponse.response)
        val responseBody = responseStr.substring(responseInfo.bodyOffset)

        val matchResults = sourceMapCommentPattern.findAll(responseBody)

        var issues = matchResults.map {
            val comment = it.value
            val sourceMapFileName = it.groups[1]!!.value

            val marked = controller.callbacks.applyMarkers(baseRequestResponse, listOf(), listOf(
               intArrayOf(it.range.first + responseInfo.bodyOffset, it.range.last + 1 + responseInfo.bodyOffset)
            ))

            PossibleSourceMapIssue(requestInfo.url, arrayOf(marked), baseRequestResponse.httpService, comment, sourceMapFileName)
        }.toMutableList()

        issues.forEach { controller.onFoundSourceMapComment(it, requestInfo) }

        return issues as MutableList<IScanIssue>
    }

    override fun doActiveScan(baseRequestResponse: IHttpRequestResponse?, insertionPoint: IScannerInsertionPoint?): MutableList<IScanIssue> = ArrayList()
}