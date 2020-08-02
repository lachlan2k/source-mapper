package burp

import SourceMapperUITab
import burp.lib.SourceMapExtractor
import burp.lib.SourceMapSourceStore
import burp.lib.checks.AnalyseMapFileCheck
import burp.lib.checks.LookForPossibleSourceMapCheck
import burp.lib.issues.PossibleSourceMapIssue
import javax.xml.transform.Source

class SourceMapperController(val callbacks: IBurpExtenderCallbacks) {
    val helpers: IExtensionHelpers = callbacks.helpers
    val store = SourceMapSourceStore()

    private val uiTab = SourceMapperUITab(this)

    init {
        callbacks.registerScannerCheck(LookForPossibleSourceMapCheck(this))
        callbacks.registerScannerCheck(AnalyseMapFileCheck(this))
        callbacks.customizeUiComponent(uiTab.uiComponent)
        callbacks.addSuiteTab(uiTab)

        println("Started SourceMapper!")
    }

    private val addedToSiteMap: MutableSet<String> = mutableSetOf()

    class SourceMapSiteMapItem (private var _request: ByteArray, private var _httpService: IHttpService) : IHttpRequestResponse {
        private var _comment = "Possible source map"
        override fun getComment() = _comment
        override fun setComment(comment: String?) = if (comment != null) _comment = comment else Unit

        private var _highlight = "Possible source map"
        override fun getHighlight() = _highlight
        override fun setHighlight(highlight: String?) = if (highlight != null) _highlight = highlight else Unit

        override fun getHttpService() = _httpService
        override fun setHttpService(service: IHttpService) { _httpService = service }

        override fun getRequest() = _request
        override fun setRequest(request: ByteArray?) = if (request != null) _request = request else Unit

        private var _response: ByteArray? = null
        override fun getResponse() = _response
        override fun setResponse(response: ByteArray?) = if (response != null) _response = response else Unit
    }

    fun onFoundSourceMapComment(issue: PossibleSourceMapIssue, requestInfo: IRequestInfo) {
        val baseUrl = requestInfo.url.toString().substringBeforeLast("/")
        val mapUrl = "$baseUrl/${issue.sourceMapFileName}"

        if (addedToSiteMap.contains(mapUrl)) return
        addedToSiteMap.add(mapUrl)

        val request = helpers.buildHttpRequest(java.net.URL(mapUrl))
        val requestResponse = SourceMapSiteMapItem(request, issue.httpService)

        callbacks.addToSiteMap(requestResponse)
    }
}