import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.Preferences;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.logging.Level;
import java.util.logging.Logger;

class DecryptTabPanel extends JPanel {
    private static final Logger LOG = Logger.getLogger(DecryptTabPanel.class.getName());
    private final MontoyaApi api;
    private final Preferences prefs;

    private static final String PREF_PREFIX = "aes_decryptor.";
    private static final String PREF_ORIGIN = PREF_PREFIX + "origin";
    private static final String PREF_AES_KEY = PREF_PREFIX + "aes_key";
    private static final String PREF_IV = PREF_PREFIX + "iv";
    private static final String PREF_RSA_PUB = PREF_PREFIX + "rsa_pub";
    private static final String PREF_KEY_MODE = PREF_PREFIX + "key_param_mode";
    private static final String PREF_ENABLED = PREF_PREFIX + "enabled";
    private static final String PREF_ENCRYPT_REPEATER = PREF_PREFIX + "encrypt_repeater";
    private static final String PREF_SET_KEY_FROM_CAPTURE = PREF_PREFIX + "set_key_from_capture";

    private final JTextField originField = new JTextField(20);
    private final JTextField aesKeyField = new JTextField(24);
    private final JTextField ivField = new JTextField(24);
    private final JTextArea rsaPublicKeyArea = new JTextArea(3, 30);
    private final JComboBox<String> keyParamMode = new JComboBox<>(new String[]{"always set", "only on POST /UserLogin"});
    private final JCheckBox enabledBox = new JCheckBox("Enabled");
    private final JCheckBox encryptRepeaterBox = new JCheckBox("Encrypt Repeater requests");
    private final JCheckBox setKeyFromCaptureBox = new JCheckBox("Set AES key from /__capture__");
    private final JButton clearBtn = new JButton("Clear");

    private final DecryptTableModel tableModel = new DecryptTableModel();
    private final JTable table = new JTable(tableModel);

    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    DecryptTabPanel(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.prefs = api.persistence().preferences();
        UserInterface ui = api.userInterface();
        this.requestEditor = ui.createHttpRequestEditor();
        this.responseEditor = ui.createHttpResponseEditor();

        // Build main decrypt UI inside its own panel
        JPanel mainPanel = new JPanel(new BorderLayout());

        JPanel controls = new JPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(2,2,2,2);
        gc.anchor = GridBagConstraints.WEST;
        gc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: Origin + toggles and actions
        gc.gridy = 0; gc.gridx = 0; gc.weightx = 0;
        controls.add(new JLabel("Target origin:"), gc);
        gc.gridx = 1; gc.weightx = 1; controls.add(originField, gc);
        gc.gridx = 2; gc.weightx = 0; controls.add(enabledBox, gc);
        gc.gridx = 3; controls.add(encryptRepeaterBox, gc);
        gc.gridx = 4; controls.add(keyParamMode, gc);
        gc.gridx = 5; controls.add(clearBtn, gc);

        // Row 1: Key/IV
        gc.gridy = 1; gc.gridx = 0; gc.weightx = 0; controls.add(new JLabel("AES key (Base64/Hex):"), gc);
        gc.gridx = 1; gc.weightx = 1; controls.add(aesKeyField, gc);
        gc.gridx = 2; gc.weightx = 0; controls.add(setKeyFromCaptureBox, gc);
        gc.gridx = 3; controls.add(new JLabel("IV (Base64/Hex):"), gc);
        gc.gridx = 4; gc.weightx = 1; controls.add(ivField, gc);

        // RSA Public Key below, spanning remaining width
        gc.gridy = 2; gc.gridx = 0; gc.weightx = 0; controls.add(new JLabel("RSA Public Key:"), gc);
        gc.gridx = 1; gc.gridwidth = 4; gc.weightx = 1;
        JScrollPane rsaScroll = new JScrollPane(rsaPublicKeyArea);
        Dimension rsaPref = rsaScroll.getPreferredSize();
        int h = rsaPref != null ? rsaPref.height : 80;
        rsaScroll.setPreferredSize(new Dimension(400, Math.max(80, h)));
        controls.add(rsaScroll, gc);
        gc.gridwidth = 1;

        clearBtn.addActionListener(e -> tableModel.clear());

        JScrollPane tableScroll = new JScrollPane(table);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JSplitPane editorsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(), responseEditor.uiComponent());
        editorsSplit.setResizeWeight(0.5);

        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                tableScroll, editorsSplit);
        verticalSplit.setResizeWeight(0.35);

        mainPanel.add(controls, BorderLayout.NORTH);
        mainPanel.add(verticalSplit, BorderLayout.CENTER);

        // Create a tabbed pane to host Decrypt UI and Hook UI inside the single Burp tab
        JTabbedPane innerTabs = new JTabbedPane();
        innerTabs.addTab("Decrypt", mainPanel);
        innerTabs.addTab("Hook", new HookTabPanel(api));

        add(innerTabs, BorderLayout.CENTER);

        ui.applyThemeToComponent(this);

        // Load persisted values first
        loadFromPreferences();

        // Wire listeners to persist on change
        attachPersistenceListeners();

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
    void setIv(String iv) { SwingUtilities.invokeLater(() -> ivField.setText(iv != null ? iv : "")); }
    String getRsaPublicKey() { return rsaPublicKeyArea.getText(); }
    String getKeyParamMode() { return (String) keyParamMode.getSelectedItem(); }
    boolean isFeatureEnabled() { return enabledBox.isSelected(); }
    boolean isEncryptRepeaterEnabled() { return encryptRepeaterBox.isSelected(); }
    boolean isSetKeyFromCaptureEnabled() { return setKeyFromCaptureBox.isSelected(); }
    void setAesKey(String key) { SwingUtilities.invokeLater(() -> aesKeyField.setText(key != null ? key : "")); }

    void addEntry(DecryptEntry e) {
        SwingUtilities.invokeLater(() -> tableModel.add(e));
    }

    void setRsaPublicKey(String key) {
        SwingUtilities.invokeLater(() -> rsaPublicKeyArea.setText(key != null ? key : ""));
    }

    void setOrigin(String origin) {
        SwingUtilities.invokeLater(() -> originField.setText(origin != null ? origin : ""));
    }

    private void loadFromPreferences() {
        try {
            String origin = prefs.getString(PREF_ORIGIN);
            if (origin != null) originField.setText(origin);
            String aes = prefs.getString(PREF_AES_KEY);
            if (aes != null) aesKeyField.setText(aes);
            String iv = prefs.getString(PREF_IV);
            if (iv != null) ivField.setText(iv);
            String rsa = prefs.getString(PREF_RSA_PUB);
            if (rsa != null) rsaPublicKeyArea.setText(rsa);
            String mode = prefs.getString(PREF_KEY_MODE);
            if (mode != null) keyParamMode.setSelectedItem(mode);
            Boolean enabled = prefs.getBoolean(PREF_ENABLED);
            enabledBox.setSelected(enabled != null && enabled);
            Boolean encRep = prefs.getBoolean(PREF_ENCRYPT_REPEATER);
            encryptRepeaterBox.setSelected(encRep != null && encRep);
            Boolean setKeyCap = prefs.getBoolean(PREF_SET_KEY_FROM_CAPTURE);
            setKeyFromCaptureBox.setSelected(setKeyCap != null && setKeyCap);
        } catch (Throwable t) {
            LOG.log(Level.FINE, "Failed to load some preferences; continuing with defaults: {0}", t.toString());
        }
    }

    private void attachPersistenceListeners() {
        DocumentListener docSave = new DocumentListener() {
            private void onChange() {
                try {
                    prefs.setString(PREF_ORIGIN, getOrigin());
                    prefs.setString(PREF_AES_KEY, getAesKey());
                    prefs.setString(PREF_IV, getIv());
                    prefs.setString(PREF_RSA_PUB, getRsaPublicKey());
                } catch (Throwable t) {
                    LOG.log(Level.FINE, "Failed to persist text preferences: {0}", t.toString());
                }
            }
            @Override public void insertUpdate(DocumentEvent e) { onChange(); }
            @Override public void removeUpdate(DocumentEvent e) { onChange(); }
            @Override public void changedUpdate(DocumentEvent e) { onChange(); }
        };
        originField.getDocument().addDocumentListener(docSave);
        aesKeyField.getDocument().addDocumentListener(docSave);
        ivField.getDocument().addDocumentListener(docSave);
        rsaPublicKeyArea.getDocument().addDocumentListener(docSave);

        ItemListener itemSave = new ItemListener() {
            @Override public void itemStateChanged(ItemEvent e) {
                try {
                    prefs.setBoolean(PREF_ENABLED, enabledBox.isSelected());
                    prefs.setBoolean(PREF_ENCRYPT_REPEATER, encryptRepeaterBox.isSelected());
                    prefs.setBoolean(PREF_SET_KEY_FROM_CAPTURE, setKeyFromCaptureBox.isSelected());
                    Object sel = keyParamMode.getSelectedItem();
                    prefs.setString(PREF_KEY_MODE, sel != null ? sel.toString() : "");
                } catch (Throwable t) {
                    LOG.log(Level.FINE, "Failed to persist checkbox/combo preferences: {0}", t.toString());
                }
            }
        };
        enabledBox.addItemListener(itemSave);
        encryptRepeaterBox.addItemListener(itemSave);
        setKeyFromCaptureBox.addItemListener(itemSave);
        keyParamMode.addItemListener(itemSave);
    }
}
