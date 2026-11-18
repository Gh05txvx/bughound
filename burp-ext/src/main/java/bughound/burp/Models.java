package bughound.burp;

import java.util.List;

// JSON models from bughound's read-only API (/api/v1/findings, see
// internal/web/api.go). Gson maps them with the
// LOWER_CASE_WITH_UNDERSCORES policy (see ApiClient), so a camelCase field
// here matches the snake_case JSON automatically (e.g. responseExcerpt takes
// response_excerpt). Only the fields the extension uses are defined;
// other JSON fields are ignored safely.

// FindingsResponse wraps the result of GET /api/v1/findings.
class FindingsResponse {
    String program;
    int count;
    List<Finding> findings;
}

// Finding: one finding in the Unified Finding Schema (the subset the Burp UI uses).
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

// Location: the finding's entry-point location.
class Location {
    String url;
    String method;
    String parameter;
}

// Evidence: the proof; `request` is the raw HTTP request sent to Repeater.
class Evidence {
    String request;
    String responseExcerpt;
    String payload;
    String matched;
}
