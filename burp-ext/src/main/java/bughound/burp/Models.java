package bughound.burp;

import java.util.List;

// Model JSON dari API baca-saja bughound (/api/v1/findings — lihat
// internal/web/api.go). Dipetakan Gson dengan kebijakan
// LOWER_CASE_WITH_UNDERSCORES (lihat ApiClient), sehingga field camelCase di
// sini otomatis cocok dengan snake_case di JSON (mis. responseExcerpt menerima
// response_excerpt). Hanya field yang dipakai extension yang didefinisikan;
// field lain di JSON diabaikan dengan aman.

// FindingsResponse membungkus hasil GET /api/v1/findings.
class FindingsResponse {
    String program;
    int count;
    List<Finding> findings;
}

// Finding: satu temuan dalam Skema Temuan Seragam (subset yang dipakai UI Burp).
class Finding {
    String id;
    String program;
    String type;
    String title;
    String severity;
    String status;
    String confidence;
    Location location;
    Evidence evidence;
}

// Location: lokasi titik masuk temuan.
class Location {
    String url;
    String method;
    String parameter;
}

// Evidence: bukti; `request` adalah request HTTP mentah yang dikirim ke Repeater.
class Evidence {
    String request;
    String responseExcerpt;
    String payload;
    String matched;
}
