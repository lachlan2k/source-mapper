package burp.lib.issues

import burp.IHttpRequestResponse
import burp.IHttpService

class SourceMapFoundIssue(_url: java.net.URL, _httpMessages: Array<IHttpRequestResponse>, _httpService: IHttpService, val filenames: Array<String>) : BaseIssue(_url, _httpMessages, _httpService) {
    private val commentHtmlList = "<ul>" + filenames.joinToString("") { "<li><b>${it}</b></li>" } + "</ul>"

    override fun getIssueName() = "Valid source map found"
    override fun getSeverity() = "Low"
    override fun getConfidence() = "Certain"
    override fun getIssueDetail() = "A source map was found with ${filenames.size} files:${commentHtmlList}"
}