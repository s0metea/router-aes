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
    private final JTextField originField = new JTextField(30);
    private final JTextField aesKeyField = new JTextField(40);
    private final JCheckBox enabledBox = new JCheckBox("Enabled");
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

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controls.add(new JLabel("Target origin:"));
        controls.add(originField);
        controls.add(new JLabel("AES key:"));
        controls.add(aesKeyField);
        controls.add(enabledBox);
        controls.add(clearBtn);

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
                        requestEditor.setRequest(de.request);
                        HttpResponse resp = de.displayedResponse != null ? de.displayedResponse : de.originalResponse;
                        responseEditor.setResponse(resp);
                    }
                }
            }
        });
    }

    String getOrigin() { return originField.getText().trim(); }
    String getAesKey() { return aesKeyField.getText().trim(); }
    boolean isFeatureEnabled() { return enabledBox.isSelected(); }

    void addEntry(DecryptEntry e) {
        SwingUtilities.invokeLater(() -> tableModel.add(e));
    }
}
