import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;

class DecryptTabPanel extends JPanel {
    private final MontoyaApi api;
    private final JTextField originField = new JTextField(20);
    private final JTextField aesKeyField = new JTextField(24);
    private final JTextField ivField = new JTextField(24);
    private final JTextArea rsaPublicKeyArea = new JTextArea(3, 30);
    private final JComboBox<String> keyParamMode = new JComboBox<>(new String[]{"always set", "only on POST /UserLogin"});
    private final JCheckBox enabledBox = new JCheckBox("Enabled");
    private final JCheckBox encryptRepeaterBox = new JCheckBox("Encrypt Repeater requests");
    private final JButton clearBtn = new JButton("Clear");

    private final DecryptTableModel tableModel = new DecryptTableModel();
    private final JTable table = new JTable(tableModel);

    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    DecryptTabPanel(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        UserInterface ui = api.userInterface();
        this.requestEditor = ui.createHttpRequestEditor();
        this.responseEditor = ui.createHttpResponseEditor();

        JPanel controls = new JPanel();
        controls.setLayout(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(2,2,2,2);
        gc.anchor = GridBagConstraints.WEST;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.gridy = 0; gc.gridx = 0;
        controls.add(new JLabel("Target origin:"), gc);
        gc.gridx = 1; controls.add(originField, gc);
        gc.gridx = 2; controls.add(enabledBox, gc);

        gc.gridy++; gc.gridx = 0; controls.add(new JLabel("AES key (Base64/Hex):"), gc);
        gc.gridx = 1; controls.add(aesKeyField, gc);
        gc.gridx = 2; controls.add(encryptRepeaterBox, gc);

        gc.gridy++; gc.gridx = 0; controls.add(new JLabel("IV (Base64/Hex):"), gc);
        gc.gridx = 1; controls.add(ivField, gc);
        gc.gridx = 2; controls.add(keyParamMode, gc);

        gc.gridy++; gc.gridx = 0; controls.add(new JLabel("RSA Public Key:"), gc);
        gc.gridx = 1; gc.gridwidth = 2;
        JScrollPane rsaScroll = new JScrollPane(rsaPublicKeyArea);
        controls.add(rsaScroll, gc);
        gc.gridwidth = 1;

        gc.gridy++; gc.gridx = 0; controls.add(clearBtn, gc);

        clearBtn.addActionListener(e -> tableModel.clear());

        JScrollPane tableScroll = new JScrollPane(table);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JSplitPane editorsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(), responseEditor.uiComponent());
        editorsSplit.setResizeWeight(0.5);

        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                tableScroll, editorsSplit);
        verticalSplit.setResizeWeight(0.35);

        add(controls, BorderLayout.NORTH);
        add(verticalSplit, BorderLayout.CENTER);

        ui.applyThemeToComponent(this);

        table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    int row = table.getSelectedRow();
                    DecryptEntry de = tableModel.get(row);
                    if (de != null) {
                        HttpRequest reqShown = de.displayedRequest != null ? de.displayedRequest : de.request;
                        requestEditor.setRequest(reqShown);
                        HttpResponse resp = de.displayedResponse != null ? de.displayedResponse : de.originalResponse;
                        responseEditor.setResponse(resp);
                    }
                }
            }
        });
    }

    String getOrigin() { return originField.getText().trim(); }
    String getAesKey() { return aesKeyField.getText().trim(); }
    String getIv() { return ivField.getText().trim(); }
    String getRsaPublicKey() { return rsaPublicKeyArea.getText(); }
    String getKeyParamMode() { return (String) keyParamMode.getSelectedItem(); }
    boolean isFeatureEnabled() { return enabledBox.isSelected(); }
    boolean isEncryptRepeaterEnabled() { return encryptRepeaterBox.isSelected(); }

    void addEntry(DecryptEntry e) {
        SwingUtilities.invokeLater(() -> tableModel.add(e));
    }

    void setRsaPublicKey(String key) {
        SwingUtilities.invokeLater(() -> rsaPublicKeyArea.setText(key != null ? key : ""));
    }
}
