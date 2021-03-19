package burp.lib.ui

import burp.SourceMapperController
import java.util.*
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel

class TopControls(private val controller: SourceMapperController) : JPanel() {
    private val exportTextLabel = JLabel("")
    private val exportButton = JButton("Export")

    interface ExportListener : EventListener {
        fun onExport();
    }

    class CallbackExportListener(val callback: () -> Unit) : ExportListener {
        override fun onExport() {
            callback()
        }
    }

    private val listeners = mutableListOf<ExportListener>()

    fun addExportListener(listener: ExportListener) {
        listeners.add(listener)
    }

    fun addExportListener(listener: () -> Unit) {
        listeners.add(CallbackExportListener(listener))
    }

    private fun notifyExportListeners() {
        listeners.forEach {
            it.onExport()
        }
    }

    var exportText: String?
        get() = exportTextLabel.text
        set(text) = if (text == null) {
            exportTextLabel.text = "<html><b>Nothing to export</b></html>"
        } else {
            exportTextLabel.text = "<html><b>Item to export:</b> $text</html>" // todo: sanitize. no xss is possible, but meh
        }

    init {
        exportText = null
        add(exportTextLabel)
        add(exportButton)

        exportButton.addActionListener {
            notifyExportListeners()
        }
    }
}