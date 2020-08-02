package burp.lib.issues

import burp.IHttpRequestResponse
import burp.IHttpService
import burp.IScanIssue

open class BaseIssue(private val _url: java.net.URL, private val _httpMessages: Array<IHttpRequestResponse>, private val _httpService: IHttpService) : IScanIssue {
    override fun getUrl() = _url

    override fun getHttpMessages() = _httpMessages
    override fun getHttpService() = _httpService

    override fun getConfidence() = "Tentative"
    override fun getSeverity() = "Low"

    override fun getIssueName() = "Issue name"
    override fun getIssueType() = 0
    override fun getIssueDetail() = "Issue detail"
    override fun getIssueBackground() = "Issue background"

    override fun getRemediationBackground() = "Remediation background"
    override fun getRemediationDetail() = "Remediation detail"
}