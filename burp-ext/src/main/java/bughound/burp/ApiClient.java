package bughound.burp;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

// ApiClient berbicara ke API JSON BACA-SAJA bughound (internal/web/api.go).
//
// - Autentikasi: HTTP Basic (jalur otomasi yang memang sudah ada di bughound).
// - Hanya GET — klien ini tidak pernah menulis/mengubah apa pun di bughound,
//   dan tidak pernah menyentuh target.
class ApiClient {
    private final Gson gson = new GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .create();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    // listFindings mengambil temuan satu program dari bughound.
    List<Finding> listFindings(String baseUrl, String user, String pass, String program) throws Exception {
        String base = baseUrl.replaceAll("/+$", "");
        String url = base + "/api/v1/findings?program="
                + URLEncoder.encode(program, StandardCharsets.UTF_8);
        String basic = Base64.getEncoder()
                .encodeToString((user + ":" + pass).getBytes(StandardCharsets.UTF_8));

        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", "Basic " + basic)
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        int code = resp.statusCode();
        if (code == 401) {
            throw new RuntimeException("401 — autentikasi gagal; cek user/password bughound");
        }
        if (code != 200) {
            throw new RuntimeException("HTTP " + code + ": " + trim(resp.body()));
        }
        FindingsResponse fr = gson.fromJson(resp.body(), FindingsResponse.class);
        return (fr != null && fr.findings != null) ? fr.findings : List.of();
    }

    private static String trim(String s) {
        if (s == null) {
            return "";
        }
        return s.length() <= 200 ? s : s.substring(0, 200) + "…";
    }
}
