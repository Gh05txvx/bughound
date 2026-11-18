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

// BughoundPanel: the contents of the 'bughound' tab in Burp.
//
// Top row   : connection form (bughound URL, user, pass, program) + "Load findings".
// Middle    : the findings table.
// Bottom row: "Send to Repeater" + status.
//
// Credentials live only in this UI's memory (not persisted): for safety the
// password is never written to disk; re-enter it each Burp session.
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

        // --- connection form ---
        JPanel form = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        form.add(new JLabel("BugHound URL:"));
        form.add(baseUrlField);
        form.add(new JLabel("user:"));
        form.add(userField);
        form.add(new JLabel("pass:"));
        form.add(passField);
        form.add(new JLabel("program:"));
        form.add(programField);
        JButton loadBtn = new JButton("Load findings");
        form.add(loadBtn);
        add(form, BorderLayout.NORTH);

        // --- findings table ---
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

        // --- actions ---
        JPanel south = new JPanel(new BorderLayout(8, 0));
        JButton sendBtn = new JButton("Send to Repeater");
        south.add(sendBtn, BorderLayout.WEST);
        south.add(status, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);

        loadBtn.addActionListener(e -> loadFindings());
        sendBtn.addActionListener(e -> sendSelectedToRepeater());
    }

    // loadFindings: pull findings from bughound on a background thread (don't block the UI).
    private void loadFindings() {
        final String base = baseUrlField.getText().trim();
        final String user = userField.getText().trim();
        final String pass = new String(passField.getPassword());
        final String program = programField.getText().trim();
        if (program.isEmpty()) {
            setStatus("Enter a program name first.", true);
            return;
        }
        setStatus("Loading…", false);
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
                    setStatus(findings.size() + " findings loaded from '" + program + "'.", false);
                } catch (Exception ex) {
                    setStatus("Load failed: " + rootMsg(ex), true);
                    api.logging().logToError("bughound: loading findings failed: " + ex);
                }
            }
        }.execute();
    }

    // sendSelectedToRepeater: rebuild the selected finding's request -> Repeater.
    private void sendSelectedToRepeater() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= findings.size()) {
            setStatus("Select a finding row first.", true);
            return;
        }
        Finding f = findings.get(row);
        if (f.location == null || f.location.url == null || f.location.url.isBlank()) {
            setStatus("The finding has no location URL, cannot send.", true);
            return;
        }
        try {
            URI uri = URI.create(f.location.url);
            String host = uri.getHost();
            if (host == null) {
                setStatus("Invalid location URL: " + f.location.url, true);
                return;
            }
            boolean secure = "https".equalsIgnoreCase(uri.getScheme());
            int port = uri.getPort() != -1 ? uri.getPort() : (secure ? 443 : 80);
            HttpService service = HttpService.httpService(host, port, secure);

            HttpRequest req;
            if (f.evidence != null && f.evidence.request != null && !f.evidence.request.isBlank()) {
                // Raw request from the engine (nuclei -include-rr, etc.).
                req = HttpRequest.httpRequest(service, f.evidence.request);
            } else {
                // No raw request, fall back to a GET to the location URL.
                req = HttpRequest.httpRequestFromUrl(f.location.url);
            }

            String tab = "bh:" + shortTitle(f);
            api.repeater().sendToRepeater(req, tab);
            setStatus("Sent to Repeater (tab '" + tab + "'). Validate manually there.", false);
        } catch (Exception ex) {
            setStatus("Send failed: " + rootMsg(ex), true);
            api.logging().logToError("bughound: send to Repeater failed: " + ex);
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
