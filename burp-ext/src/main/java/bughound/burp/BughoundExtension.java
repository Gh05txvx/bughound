package bughound.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

// Entry point of the bughound Burp extension (Montoya API).
//
// Goal: pull findings from bughound into Burp, then "Send to Repeater"
// for manual validation, without leaving the tool.
//
// Deliberate limits (in line with bughound's security principles):
//   - The extension only READS from bughound (GET /api/v1/findings) and loads
//     a request into Repeater. It writes nothing back to bughound.
//   - Sending a request to a target stays YOUR MANUAL action in Repeater
//     (the Send button). No auto-submit, no automatic scan from here.
public class BughoundExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("BugHound");
        BughoundPanel panel = new BughoundPanel(api);
        api.userInterface().registerSuiteTab("BugHound", panel);
        api.logging().logToOutput("bughound: extension loaded, open the 'BugHound' tab.");
    }
}
