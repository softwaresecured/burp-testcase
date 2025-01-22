/*
    Test case which demonstrates that AuditInsertionPoints provided by a AuditInsertionPointProvider will not report
    issues in the scan
 */
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpInjector implements BurpExtension, AuditInsertionPointProvider {
    private MontoyaApi api;
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        api = montoyaApi;
        // Register as an insertion point provider
        api.scanner().registerInsertionPointProvider(this);
    }

    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse httpRequestResponse) {
        /*
            Provide an insertion point provider for the "case_encode" endpoint which accepts a base64 encoded value with
            a reversed string inside of it
         */
        ArrayList<AuditInsertionPoint> insertionPoints = new ArrayList<AuditInsertionPoint>();
        // Check if the request is to /case_encode
        if ( httpRequestResponse.request().url().matches(".*case_encode.*")) {
            // Check if the request contains arg1 body parameter
            String requestBody = httpRequestResponse.request().bodyToString();
            Pattern p = Pattern.compile("arg1=(.*?)");
            Matcher m = p.matcher(requestBody);
            if ( m.find()) {
                if ( m.groupCount() >= 1 ) {
                    String rawValue = m.group(1);
                    String urlDecoded = URLDecoder.decode(rawValue, StandardCharsets.UTF_8);
                    // Build an insertion point for arg1 of the /case_encode request
                    AuditInsertionPoint auditInsertionPoint = new AuditInsertionPoint() {
                        private String baseValue = Arrays.toString(Base64.getDecoder().decode(urlDecoded));
                        private String encodePayload( String payload ) {
                            String base64Encoded = Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
                            return URLEncoder.encode(base64Encoded);
                        }

                        @Override
                        public String name() {
                            return "arg1";
                        }

                        @Override
                        public String baseValue() {
                            return baseValue;
                        }

                        @Override
                        public HttpRequest buildHttpRequestWithPayload(ByteArray byteArray) {
                            // Build a new request body with the payload reversed and base64 encoded
                            StringBuilder payload = new StringBuilder(String.valueOf(byteArray)).reverse();
                            String body = String.format("arg1=%s", encodePayload(payload.toString()));
                            api.logging().raiseDebugEvent(String.format("buildHttpRequestWithPayload called for payload [%s]", new String(String.valueOf(byteArray))));
                            // Return the rebuilt request with a "TESTREQUEST" header so it is easy to locate in a scan report
                            return httpRequestResponse.request().withBody(body).withAddedHeader("TESTREQUEST","THIS_IS_THE_TEST_REQUEST");
                        }

                        @Override
                        public List<Range> issueHighlights(ByteArray byteArray) {
                            return List.of();
                        }
                    };
                    insertionPoints.add(auditInsertionPoint);
                }
            }
        }
        api.logging().raiseDebugEvent(String.format("Returning %d custom insertion points", insertionPoints.size()));
        return insertionPoints;
    }
}