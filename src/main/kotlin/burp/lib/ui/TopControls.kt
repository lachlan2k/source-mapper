package burp.lib.ui

import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel

class TopControls : JPanel() {
    private val exportTextLabel = JLabel("")
    private val exportButton = JButton("Export")

    var exportText: String?
        get() = exportTextLabel.text
        set(text: String?) = if (text == null) {
            exportTextLabel.text = "<html><b>Nothing to export</b></html>"
        } else {
            exportTextLabel.text = "<html><b>Item to export:</b> $text</html>"
        }

    init {
        exportText = null
        add(exportTextLabel)
        add(exportButton)
    }
}