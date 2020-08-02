import burp.ITab
import burp.SourceMapperController
import burp.lib.SourceMapExtractor
import burp.lib.SourceMapSourceStore
import burp.lib.ui.FileBrowser
import burp.lib.ui.TopControls
import java.io.File
import javax.swing.JSplitPane
import javax.swing.tree.DefaultMutableTreeNode

class SourceMapperUITab(private val controller: SourceMapperController) : ITab, JSplitPane(JSplitPane.VERTICAL_SPLIT) {
    override fun getUiComponent() = this
    override fun getTabCaption() = "SourceMapper"

    private val fileBrowser = FileBrowser(controller)
    private val topControls = TopControls()

    init {
        topComponent = topControls
        bottomComponent = fileBrowser

        fileBrowser.tree.addTreeSelectionListener {
            val selectedNode = fileBrowser.tree.lastSelectedPathComponent

            if (selectedNode is SourceMapSourceStore.TreeFile || selectedNode is SourceMapSourceStore.TreeFolder) {
                topControls.exportText = selectedNode.toString()
            }
        }
    }
}