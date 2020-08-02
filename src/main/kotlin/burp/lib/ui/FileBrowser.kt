package burp.lib.ui

import burp.IHttpService
import burp.IMessageEditorController
import burp.SourceMapperController
import burp.lib.SourceMapSourceStore
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTree
import javax.swing.ScrollPaneConstants
import javax.swing.event.TreeModelListener
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.TreeModel
import javax.swing.tree.TreePath

class FileBrowser(private val controller: SourceMapperController) : JSplitPane(JSplitPane.HORIZONTAL_SPLIT) {
    open class NodeFolderPathData(val pathLevels: List<String>) {
        override fun toString () = if (pathLevels.isEmpty()) "SourceMapper" else pathLevels.last()
    }

    class NodeFileContentAndPathData(pathLevels: List<String>, val content: String) : NodeFolderPathData(pathLevels) {}

    class EditorController() : IMessageEditorController {
        private var _request: ByteArray? = null
        private var _response: ByteArray? = null
        private var _httpService: IHttpService? = null

        override fun getResponse() = _response
        override fun getRequest() = _request
        override fun getHttpService() = _httpService

        fun setResponse(newResponse: ByteArray?) {
            _response = newResponse
        }
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