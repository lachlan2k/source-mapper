package burp.lib.ui

import burp.ITab
import burp.SourceMapperController
import burp.lib.SourceMapSourceStore
import java.io.File
import javax.swing.JFileChooser
import javax.swing.JSplitPane

class SourceMapperUITab(private val controller: SourceMapperController) : ITab, JSplitPane(VERTICAL_SPLIT) {
    override fun getUiComponent() = this
    override fun getTabCaption() = "SourceMapper"

    private val fileBrowser = FileBrowser(controller)
    private val topControls = TopControls(controller)
    private var nodeToExport: Any? = null

    private fun exportFolder (folder: SourceMapSourceStore.TreeFolder) {
        val chooser = JFileChooser()
        chooser.dialogTitle = "Choose a directory to export ${folder.name} to:"
        chooser.fileSelectionMode = JFileChooser.DIRECTORIES_ONLY

        if (chooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
            println("Saving to ${chooser.selectedFile.absolutePath}")
        }
    }

    private fun exportFile (file: SourceMapSourceStore.TreeFile) {
        val chooser = JFileChooser()
        chooser.dialogTitle = "Choose a directory to export ${file.name} to:"
        chooser.selectedFile = File(file.name)

        if (chooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
            println("Saving to ${chooser.selectedFile.absolutePath}")
        }
    }

    fun onExport() = nodeToExport.let { node ->
        when (node) {
            is SourceMapSourceStore.TreeFile -> exportFile(node)
            is SourceMapSourceStore.TreeFolder -> exportFolder(node)
            else -> Unit
        }
    }

    init {
        topComponent = topControls
        bottomComponent = fileBrowser

        fileBrowser.tree.addTreeSelectionListener {
            val selectedNode = fileBrowser.tree.lastSelectedPathComponent

            if (selectedNode is SourceMapSourceStore.TreeFile || selectedNode is SourceMapSourceStore.TreeFolder) {
                nodeToExport = selectedNode
                topControls.exportText = nodeToExport.toString()
            }
        }
    }
}