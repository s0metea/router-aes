import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

class DecryptEntry {
    final long timestamp;
    final HttpRequest request;
    final HttpResponse originalResponse;
    final HttpResponse displayedResponse;
    final boolean decrypted;
    final String note;

    DecryptEntry(long timestamp, HttpRequest request, HttpResponse originalResponse, HttpResponse displayedResponse, boolean decrypted, String note) {
        this.timestamp = timestamp;
        this.request = request;
        this.originalResponse = originalResponse;
        this.displayedResponse = displayedResponse;
        this.decrypted = decrypted;
        this.note = note;
    }
}
