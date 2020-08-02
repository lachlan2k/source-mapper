package burp.lib.ui

import burp.IHttpService
import burp.IMessageEditorController
import burp.SourceMapperController
import burp.lib.SourceMapSourceStore
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTree
import javax.swing.ScrollPaneConstants

class FileBrowser(private val controller: SourceMapperController) : JSplitPane(HORIZONTAL_SPLIT) {
    class EditorController : IMessageEditorController {
        private var _request: ByteArray? = null
        private var _response: ByteArray? = null
        private var _httpService: IHttpService? = null

        override fun getResponse() = _response
        override fun getRequest() = _request
        override fun getHttpService() = _httpService
    }

    private val editorController = EditorController()
    private val editor = controller.callbacks.createMessageEditor(editorController, false)

    val tree = JTree(controller.store)
    private val treeScrollContainer = JScrollPane(tree, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)

    init {
        tree.addTreeSelectionListener { onTreeSelect() }

        setLeftComponent(treeScrollContainer)
        setRightComponent(editor.component)
        dividerLocation = 350
    }

    private fun onTreeSelect() {
        val selectedNode = tree.lastSelectedPathComponent ?: return

        if (selectedNode is SourceMapSourceStore.TreeFile) {
            val contentBytes = controller.helpers.stringToBytes(selectedNode.contents)
            editor.setMessage(contentBytes, false)
        }
    }
}