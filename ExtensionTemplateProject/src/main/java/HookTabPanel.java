import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.UserInterface;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;

class HookTabPanel extends JPanel {
    private final MontoyaApi api;
    private final Preferences prefs;
    private final JTextArea hookArea = new JTextArea();
    private final JButton resetBtn = new JButton("Reset to default");
    private final JTextField hookPathField = new JTextField(30);

    HookTabPanel(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.prefs = api.persistence().preferences();

        UserInterface ui = api.userInterface();

        JLabel lbl = new JLabel("Custom JS hook (persisted)");
        lbl.setBorder(BorderFactory.createEmptyBorder(6,6,6,6));

        hookArea.setLineWrap(true);
        hookArea.setWrapStyleWord(true);
        hookArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scroll = new JScrollPane(hookArea);

        JPanel top = new JPanel(new BorderLayout());
        top.add(lbl, BorderLayout.WEST);
        top.add(resetBtn, BorderLayout.EAST);

        // Bottom bar for path configuration
        JPanel bottom = new JPanel(new BorderLayout());
        JLabel pathLbl = new JLabel("Hook path to inject (default: /static/js/app.js): ");
        bottom.add(pathLbl, BorderLayout.WEST);
        bottom.add(hookPathField, BorderLayout.CENTER);

        add(top, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);

        // Load initial values (default if not set)
        String current = HookSettings.getHook(prefs);
        hookArea.setText(current);
        hookPathField.setText(HookSettings.getHookPath(prefs));

        // Persist on change (simple document listener)
        hookArea.getDocument().addDocumentListener(new DocumentListener() {
            private void save() {
                HookSettings.setHook(prefs, hookArea.getText());
            }
            @Override public void insertUpdate(DocumentEvent e) { save(); }
            @Override public void removeUpdate(DocumentEvent e) { save(); }
            @Override public void changedUpdate(DocumentEvent e) { save(); }
        });

        hookPathField.getDocument().addDocumentListener(new DocumentListener() {
            private void save() {
                HookSettings.setHookPath(prefs, hookPathField.getText());
            }
            @Override public void insertUpdate(DocumentEvent e) { save(); }
            @Override public void removeUpdate(DocumentEvent e) { save(); }
            @Override public void changedUpdate(DocumentEvent e) { save(); }
        });

        // Reset button reverts to default
        resetBtn.addActionListener(e -> {
            String def = HookSettings.defaultHook();
            hookArea.setText(def);
            HookSettings.setHook(prefs, def);
            hookPathField.setText(HookSettings.DEFAULT_HOOK_PATH);
            HookSettings.setHookPath(prefs, HookSettings.DEFAULT_HOOK_PATH);
        });

        ui.applyThemeToComponent(this);
    }
}
