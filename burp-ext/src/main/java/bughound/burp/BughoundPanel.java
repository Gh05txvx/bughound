package bughound.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.net.URI;
import java.util.List;

// BughoundPanel: isi tab 'bughound' di Burp.
//
// Baris atas  : form koneksi (URL bughound, user, pass, program) + "Muat temuan".
// Tengah      : tabel temuan.
// Baris bawah : "Kirim ke Repeater" + status.
//
// Kredensial hanya disimpan di memori UI ini (tidak dipersist) — demi keamanan,
// password tidak ditulis ke disk; isi ulang tiap sesi Burp.
class BughoundPanel extends JPanel {
    private final MontoyaApi api;
    private final ApiClient client = new ApiClient();

    private final JTextField baseUrlField = new JTextField("http://127.0.0.1:8787", 20);
    private final JTextField userField = new JTextField("admin", 8);
    private final JPasswordField passField = new JPasswordField(12);
    private final JTextField programField = new JTextField(14);
    private final JLabel status = new JLabel(" ");
    private final DefaultTableModel tableModel;
    private final JTable table;

    private List<Finding> findings = List.of();

    BughoundPanel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // --- form koneksi ---
        JPanel form = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        form.add(new JLabel("bughound URL:"));
        form.add(baseUrlField);
        form.add(new JLabel("user:"));
        form.add(userField);
        form.add(new JLabel("pass:"));
        form.add(passField);
        form.add(new JLabel("program:"));
        form.add(programField);
        JButton loadBtn = new JButton("Muat temuan");
        form.add(loadBtn);
        add(form, BorderLayout.NORTH);

        // --- tabel temuan ---
        tableModel = new DefaultTableModel(new Object[]{"Severity", "Type", "Title", "Method", "URL"}, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        add(new JScrollPane(table), BorderLayout.CENTER);

        // --- aksi ---
        JPanel south = new JPanel(new BorderLayout(8, 0));
        JButton sendBtn = new JButton("Kirim ke Repeater");
        south.add(sendBtn, BorderLayout.WEST);
        south.add(status, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);

        loadBtn.addActionListener(e -> loadFindings());
        sendBtn.addActionListener(e -> sendSelectedToRepeater());
    }

    // loadFindings: tarik temuan dari bughound di thread latar (jangan blok UI).
    private void loadFindings() {
        final String base = baseUrlField.getText().trim();
        final String user = userField.getText().trim();
        final String pass = new String(passField.getPassword());
        final String program = programField.getText().trim();
        if (program.isEmpty()) {
            setStatus("Isi nama program dulu.", true);
            return;
        }
        setStatus("Memuat…", false);
        new SwingWorker<List<Finding>, Void>() {
            @Override
            protected List<Finding> doInBackground() throws Exception {
                return client.listFindings(base, user, pass, program);
            }

            @Override
            protected void done() {
                try {
                    findings = get();
                    tableModel.setRowCount(0);
                    for (Finding f : findings) {
                        tableModel.addRow(new Object[]{
                                f.severity,
                                f.type,
                                f.title,
                                f.location != null ? f.location.method : "",
                                f.location != null ? f.location.url : ""
                        });
                    }
                    setStatus(findings.size() + " temuan dimuat dari '" + program + "'.", false);
                } catch (Exception ex) {
                    setStatus("Gagal muat: " + rootMsg(ex), true);
                    api.logging().logToError("bughound: muat temuan gagal: " + ex);
                }
            }
        }.execute();
    }

    // sendSelectedToRepeater: rekonstruksi request temuan terpilih → Repeater.
    private void sendSelectedToRepeater() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= findings.size()) {
            setStatus("Pilih satu baris temuan dulu.", true);
            return;
        }
        Finding f = findings.get(row);
        if (f.location == null || f.location.url == null || f.location.url.isBlank()) {
            setStatus("Temuan tak punya URL lokasi — tak bisa dikirim.", true);
            return;
        }
        try {
            URI uri = URI.create(f.location.url);
            String host = uri.getHost();
            if (host == null) {
                setStatus("URL lokasi tak valid: " + f.location.url, true);
                return;
            }
            boolean secure = "https".equalsIgnoreCase(uri.getScheme());
            int port = uri.getPort() != -1 ? uri.getPort() : (secure ? 443 : 80);
            HttpService service = HttpService.httpService(host, port, secure);

            HttpRequest req;
            if (f.evidence != null && f.evidence.request != null && !f.evidence.request.isBlank()) {
                // Request mentah dari engine (nuclei -include-rr, dll).
                req = HttpRequest.httpRequest(service, f.evidence.request);
            } else {
                // Tak ada request mentah — fallback GET ke URL lokasi.
                req = HttpRequest.httpRequestFromUrl(f.location.url);
            }

            String tab = "bh:" + shortTitle(f);
            api.repeater().sendToRepeater(req, tab);
            setStatus("Terkirim ke Repeater (tab '" + tab + "'). Validasi manual di sana.", false);
        } catch (Exception ex) {
            setStatus("Gagal kirim: " + rootMsg(ex), true);
            api.logging().logToError("bughound: kirim ke Repeater gagal: " + ex);
        }
    }

    private static String shortTitle(Finding f) {
        String t = (f.title != null) ? f.title : f.type;
        if (t == null) {
            t = "finding";
        }
        t = t.replaceAll("\\s+", " ").trim();
        return t.length() > 24 ? t.substring(0, 24) : t;
    }

    private void setStatus(String msg, boolean error) {
        status.setText(msg);
        status.setForeground(error ? new Color(0xB0, 0x30, 0x30) : new Color(0x2E, 0x7D, 0x32));
    }

    private static String rootMsg(Throwable ex) {
        Throwable c = ex;
        while (c.getCause() != null) {
            c = c.getCause();
        }
        return (c.getMessage() != null) ? c.getMessage() : c.toString();
    }
}
