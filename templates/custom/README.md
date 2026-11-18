# BugHound custom detection templates (Payload Bank)

This directory holds the **home-grown** nuclei templates that the `nuclei-custom`
runner runs (see `BH-SPEC-PAYLOAD` and the `cmd/bughound` roster). The runner
calls `nuclei -t <this dir>`, so **only** the templates here run, separate from
the official `nuclei` runner that uses the full built-in set.

## Rules (binding)

1. **Read-only only.** Templates here must be non-destructive: detect through a
   read request (GET, or a read query such as GraphQL introspection). Do not
   write, change, or delete target state, upload a file, or trigger a DoS. The
   `dos`/`smuggling` tags and unsafe IDs are still blocked structurally by
   `nonDestructiveArgs()`, but do not lean on that; write a template that is
   safe on its own.
2. **Do not drag secrets into evidence.** Match structural markers (key patterns,
   field names), not the sensitive values themselves.
3. **One finding = one clear class.** Include `classification.cwe-id` and `tags`
   so the normalization to OWASP + actionable remediation works in the draft report.

## Activation

Opt-in runner: add `nuclei-custom` to the `-engine` list **and** point it at the dir:

```
-engine nuclei,ffuf,zap,nuclei-dast,dalfox,nuclei-custom \
-custom-templates ./templates/custom      # or env BUGHOUND_CUSTOM_TEMPLATES
```

In the image this dir is COPIED to `/app/templates/custom` and the
`BUGHOUND_CUSTOM_TEMPLATES` env points there.
