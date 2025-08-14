import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.HttpService;

import javax.swing.*;
import java.awt.Component;
import java.util.Collections;
import java.util.List;

class OriginContextMenuProvider implements ContextMenuItemsProvider {
    private final DecryptTabPanel panel;

    OriginContextMenuProvider(DecryptTabPanel panel) {
        this.panel = panel;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        try {
            List<HttpRequestResponse> sel = event.selectedRequestResponses();
            if (sel == null || sel.isEmpty()) {
                return Collections.emptyList();
            }
            HttpRequestResponse rr = sel.get(0);
            if (rr == null) return Collections.emptyList();
            HttpService svc = rr.httpService();
            if (svc == null) return Collections.emptyList();
            String origin = buildOrigin(svc);
            if (origin == null || origin.isEmpty()) return Collections.emptyList();

            JMenuItem item = new JMenuItem("AES Decryptor: Set origin to " + origin);
            item.addActionListener(e -> panel.setOrigin(origin));
            return Collections.singletonList(item);
        } catch (Throwable t) {
            return Collections.emptyList();
        }
    }

    private static String buildOrigin(HttpService svc) {
        try {
            String host = svc.host();
            int port = svc.port();
            boolean tls = svc.secure();
            if (host == null || host.isEmpty()) return null;
            String scheme = tls ? "https" : "http";
            boolean omitPort = (tls && port == 443) || (!tls && port == 80);
            String portPart = omitPort ? "" : (":" + port);
            return scheme + "://" + host + portPart;
        } catch (Throwable t) {
            return null;
        }
    }
}
