package burp.lib

import java.nio.file.Path
import java.nio.file.Paths

class FolderExporter(private val root: SourceMapSourceStore.TreeFolder, private val absoluteParentPath: Path) {
    private fun exportFile(file: SourceMapSourceStore.TreeFile, path: Array<String>) {
        val absPath = absoluteParentPath.resolve(Paths.get("/", *path).normalize().toString().removePrefix("/"))
        val outFile = absPath.toFile()

        try {
            outFile.parentFile.mkdirs()
            outFile.writeText(file.contents)
        } catch (e: Error) {} // probably don't have permissions
    }

    private fun filterPathStr(str: String): String {
        return str
                .removePrefix("https://")
                .removePrefix("http://")
                .removeSuffix("/")
                .replace('/', '_')
    }

    private fun concatPathStr(path: Array<String>, next: String): Array<String> {
        return path.plus(filterPathStr(next))
    }

    private fun recursivelyExport(node: SourceMapSourceStore.TreeFolder, path: Array<String>) {
        node.files.forEach {
            exportFile(it.value, concatPathStr(path, it.key))
        }

        node.folders.forEach {
            recursivelyExport(it.value, concatPathStr(path, it.key))
        }
    }

    fun export() {
        synchronized(root) {
            recursivelyExport(root, arrayOf(filterPathStr(root.name)))
        }
    }
}