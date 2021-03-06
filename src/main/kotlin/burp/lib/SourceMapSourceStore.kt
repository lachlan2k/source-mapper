package burp.lib

import java.util.*
import javax.swing.event.TreeModelEvent
import javax.swing.event.TreeModelListener
import javax.swing.tree.TreeModel
import javax.swing.tree.TreePath

class SourceMapSourceStore : TreeModel {
    class TreeFile(val name: String, val contents: String) {
        override fun toString() = name
    }

    class TreeFolder(val name: String) {
        public val folders = TreeMap<String, TreeFolder>()
        public val files = TreeMap<String, TreeFile>()

        fun getSize() = folders.size + files.size
        fun get(index: Int): Any = when {
            index >= folders.size -> files.values.toTypedArray()[index - folders.size]
            else -> folders.values.toTypedArray()[index]
        }

        override fun toString() = name
    }

    private val data = TreeFolder("Sources")
    private val filterWebpackProtocolPattern = """^(webpack://)?/?""".toRegex()

    private val listeners = HashSet<TreeModelListener>()

    override fun removeTreeModelListener(listener: TreeModelListener?) {
        listeners.remove(listener)
    }

    override fun addTreeModelListener(listener: TreeModelListener?) {
        if (listener != null) listeners.add(listener)
    }

    private fun notifyListeners() {
        listeners.forEach {
            it.treeStructureChanged(TreeModelEvent(this, arrayOf(root)))
            it.treeNodesChanged(TreeModelEvent(this, arrayOf(root)))
        }
    }

    private fun constructUrlBase(url: java.net.URL): String {
        var port = url.port

        if ((url.protocol == "http" && port == 80) || (url.protocol == "https" && port == 443)) {
            port = -1
        }

        return when (port) {
            -1 -> "${url.protocol}://${url.host}/"
            else -> "${url.protocol}://${url.host}:$port/"
        }
    }

    fun insert(sourceMapUrl: java.net.URL, files: List<SourceMapExtractor.SourceMapFile>) {
        val base = constructUrlBase(sourceMapUrl)
        val sourceMapFolderPathLevels = sourceMapUrl.path.substringBeforeLast("/").trimStart('/').split("/").dropLast(1)

        synchronized(this) {
            files.forEach { file ->
                val sourceFileFolderPathLevels = filterWebpackProtocolPattern.replace(file.sourcePath, "").split("/")
                val completePathLevels = listOf(base) + sourceMapFolderPathLevels + sourceFileFolderPathLevels
                val sourceFileName = completePathLevels.last()

                var cursor = data

                completePathLevels.dropLast(1).forEach {
                    cursor = cursor.folders.getOrPut(it) { TreeFolder(it) }
                }

                cursor.files[sourceFileName] = TreeFile(sourceFileName, file.sourceContents)
            }

            notifyListeners()
        }
    }

    fun getFolder(pathLevels: List<String>): TreeFolder? {
        synchronized(this) {
            var cursor: TreeFolder? = data

            pathLevels.forEach {
                cursor = cursor?.folders?.get(it)
            }

            return cursor
        }
    }

    fun getFile(pathLevels: List<String>): TreeFile? {
        synchronized(this) {
            val folder = getFolder(pathLevels.dropLast(1))
            val fileName = pathLevels.last()

            return folder?.files?.get(fileName)
        }
    }

    override fun getRoot(): Any {
        return data
    }

    override fun isLeaf(node: Any?) = node is TreeFile

    override fun getChildCount(parent: Any?) = synchronized(this) {
        when (parent) {
            is TreeFile -> 0
            is TreeFolder -> parent.folders.size + parent.files.size
            else -> 0
        }
    }

    override fun getIndexOfChild(parent: Any?, child: Any?): Int = synchronized(this) {
        when (parent) {
            is TreeFolder -> when (child) {
                is TreeFolder -> parent.folders.values.indexOf(child)
                is TreeFile -> parent.files.values.indexOf(child) + parent.folders.size
                else -> 0
            }
            else -> 0
        }
    }

    override fun getChild(parent: Any?, index: Int) = synchronized(this) {
        when (parent) {
            is TreeFolder -> parent.get(index)
            else -> null
        }
    }

    override fun valueForPathChanged(path: TreePath?, newValue: Any?) {}
}