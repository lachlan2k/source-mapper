package burp.lib.issues

import burp.IHttpRequestResponse
import burp.IHttpService

class PossibleSourceMapIssue(_url: java.net.URL, _httpMessages: Array<IHttpRequestResponse>, _httpService: IHttpService, val extractedComment: String, val sourceMapFileName: String) : BaseIssue(_url, _httpMessages, _httpService) {
    override fun getIssueName() = "Possible source map"
    override fun getSeverity() = "Information"
    override fun getConfidence() = "Tentative"
    override fun getIssueDetail() = "The following source map comment was found: ${extractedComment}"
}