package burp.lib

import com.google.gson.Gson
import com.google.gson.JsonParseException

class SourceMapExtractor(private val body: String) {
    private class SourceMap(val sources: Array<String>, val sourcesContent: Array<String>)
    private var loadedSourceMap: SourceMap

    class InvalidSourceMapException(message: String) : Exception("The source map provided was not in a valid format. $message")
    class SourceMapFile(val sourcePath: String, val sourceContents: String)

    init {
        try {
            loadedSourceMap = Gson().fromJson(body, SourceMap::class.java)
        } catch (e: JsonParseException) {
            throw InvalidSourceMapException("Could not parse source map JSON to valid format.")
        }

        if (loadedSourceMap.sources.size != loadedSourceMap.sourcesContent.size) {
            throw InvalidSourceMapException("Length of sources ${loadedSourceMap.sources.size} did not match length of sourcesContent ${loadedSourceMap.sourcesContent.size}.")
        }
    }

    val filenames
        get() = loadedSourceMap.sources

    val files
        get() = loadedSourceMap.sources.zip(loadedSourceMap.sourcesContent)
        { sourcePath, sourceContents -> SourceMapFile(sourcePath, sourceContents) }
}