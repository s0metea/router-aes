import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.table.AbstractTableModel;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

class DecryptTableModel extends AbstractTableModel {
    private final List<DecryptEntry> entries = new ArrayList<>();
    private final String[] columns = {"Time", "Method", "URL", "Status", "Decrypted", "Note"};
    private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss");

    public void add(DecryptEntry entry) {
        int idx = entries.size();
        entries.add(entry);
        fireTableRowsInserted(idx, idx);
    }

    public DecryptEntry get(int row) {
        if (row < 0 || row >= entries.size()) return null;
        return entries.get(row);
    }

    public void clear() {
        int size = entries.size();
        entries.clear();
        if (size > 0) fireTableRowsDeleted(0, size - 1);
    }

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public String getColumnName(int column) {
        return columns[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        DecryptEntry e = entries.get(rowIndex);
        HttpRequest req = e.displayedRequest != null ? e.displayedRequest : e.request;
        HttpResponse resp = e.displayedResponse != null ? e.displayedResponse : e.originalResponse;
        return switch (columnIndex) {
            case 0 -> fmt.format(new Date(e.timestamp));
            case 1 -> safe(() -> req.method());
            case 2 -> safe(() -> req.url());
            case 3 -> safe(() -> String.valueOf(resp.statusCode()));
            case 4 -> e.decrypted;
            case 5 -> e.note;
            default -> "";
        };
    }

    private String safe(SupplierWithEx<String> s) {
        try { return s.get(); } catch (Throwable t) { return ""; }
    }

    interface SupplierWithEx<T> { T get(); }
}
