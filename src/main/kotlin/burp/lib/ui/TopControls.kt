package burp.lib.ui

import burp.SourceMapperController
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel

class TopControls(private val controller: SourceMapperController) : JPanel() {

    private val exportTextLabel = JLabel("")
    private val exportButton = JButton("Export")

    var exportText: String?
        get() = exportTextLabel.text
        set(text) = if (text == null) {
            exportTextLabel.text = "<html><b>Nothing to export</b></html>"
        } else {
            exportTextLabel.text = "<html><b>Item to export:</b> $text</html>"
        }

    init {
        exportText = null
        add(exportTextLabel)
        add(exportButton)

        exportButton.addActionListener {
            JOptionPane.showOptionDialog(
                this, "Export doesn't work yet, sorry. :(", "I'm really sorry", JOptionPane.OK_OPTION,
                JOptionPane.PLAIN_MESSAGE, null, arrayOf("It's okay, Lachlan"), "It's okay, Lachlan")
        }
    }
}