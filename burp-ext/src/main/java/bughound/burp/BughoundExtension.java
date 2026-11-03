package bughound.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

// Titik masuk extension Burp bughound (Montoya API).
//
// Tujuan: menarik temuan dari bughound ke dalam Burp, lalu "Kirim ke Repeater"
// untuk validasi manual — tanpa pindah tool.
//
// Batas yang disengaja (sejalan prinsip keamanan bughound):
//   - Extension HANYA MEMBACA dari bughound (GET /api/v1/findings) dan memuat
//     request ke Repeater. Ia tidak menulis apa pun ke bughound.
//   - Mengirim request ke target tetap AKSI MANUAL kamu di Repeater
//     (tombol Send). Tidak ada auto-submit, tidak ada scan otomatis dari sini.
public class BughoundExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("bughound");
        BughoundPanel panel = new BughoundPanel(api);
        api.userInterface().registerSuiteTab("bughound", panel);
        api.logging().logToOutput("bughound: extension dimuat — buka tab 'bughound'.");
    }
}
