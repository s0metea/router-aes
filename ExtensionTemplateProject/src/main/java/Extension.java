import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("AES-CBC Auto Decrypter");

        DecryptTabPanel panel = new DecryptTabPanel(montoyaApi);
        Registration tabReg = montoyaApi.userInterface().registerSuiteTab("AES Decrypt", panel);

        montoyaApi.http().registerHttpHandler(new DecryptingHttpHandler(montoyaApi, panel));
    }
}