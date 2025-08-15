import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("AES-CBC Auto Decrypter");
        try {
            montoyaApi.logging().logToOutput("[AES-Decrypter] Extension initialized");
            montoyaApi.logging().raiseInfoEvent("AES-CBC Auto Decrypter loaded");
        } catch (Throwable ignored) {}

        DecryptTabPanel panel = new DecryptTabPanel(montoyaApi);
        Registration tabReg = montoyaApi.userInterface().registerSuiteTab("AES Decrypt", panel);

        // Context menu to set origin from selected request
        Registration ctxReg = montoyaApi.userInterface().registerContextMenuItemsProvider(new OriginContextMenuProvider(panel));

        montoyaApi.http().registerHttpHandler(new DecryptingHttpHandler(montoyaApi, panel));
        // Intercept capture beacons and drop them
        montoyaApi.proxy().registerRequestHandler(new CaptureProxyHandler(montoyaApi, panel));
    }
}