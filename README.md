# Description
This testcase demonstrates that AuditInsertionPoint objects provided to the scanner will not be included in scan results
if a vulnerability is discovered.

### The testcase is comprised of the following:
- A simple java extension called `BurpInjector.java` which returns 1 insertion point
- `tasecase-92.py` which is a python application that contains 1 command injection ( runs on linux )
- `test.bcheck` which is a BCheck that tests for one command injection type using a collaborator server to validate the result

### Observations:
- This issue is not specific to BChecks or collaborator verified payloads
- This issue is not specific to the location of the insertion point

# Preparation

- Run BurpSuite and create a new temporary project in memory
- Run the test application using `python3 testcase-92.py`
- In Burp, Click Target → Scope → Add and add `http://localhost:4444` to the project scope
- Run the test curl commands below to send both test requests through the proxy:

```
curl -x localhost:8080 -X POST http://localhost:4444/case_noencode -d 'arg1=hostname' -H 'Content-Type: application/x-www-form-urlencoded'
curl -x localhost:8080 -X POST http://localhost:4444/case_encode -d 'arg1=%59%47%46%6a%4c%6a%45%74%63%33%4d%75%62%44%5a%33%61%54%46%6c%4f%48%46%6f%61%33%46%35%64%6a%4e%69%61%6a%56%6b%5a%54%64%70%4e%6e%6c%6c%61%57%6c%6a%64%47%5a%6d%5a%7a%51%77%4e%69%42%73%63%6e%56%6a%59%41%3d%3d' -H 'Content-Type: application/x-www-form-urlencoded'
```
- Observe that in both cases the hostname is shown.
- Download the extension from the releases tab https://github.com/softwaresecured/burp-testcase/releases/tag/demo
- In Burp, click Extensions → Add and select "Java" as the extension type. Click "Select file" and select `testcase-92-0.1.1.jar`

# Bcheck demo
A BCheck is used to speed up the scan and only test for one issue but a full scan can be used if preferred.
### Configure the bcheck:
- Click Extensions → BChecks and highlight all the BChecks. Disable all of them since we'll only be using one for the scan
- Click New → Blank
- Enter the code from `test.bcheck` (https://github.com/softwaresecured/burp-testcase/blob/main/test.bcheck)
- Click save

### Run the scans
- Click the proxy tab and right click the reqeust to `/case_encode` and click "Scan"
- Click "Scan configuration" and click "New" to create a new scan profile
- Under the issues reported section, select the "Select individual issues" radio button and disable all issues
- Search for "Bcheck" and enable only "BCheck generated issue"
- Click Save and then click "Scan" to start the scan
- Once the scan completes, observe that the scan completes without finding any vulnerabilities
- Click the logger tab and locate the request containing the header `THIS_IS_THE_TEST_REQUEST`
- Right click on it and send it to the repeater
- Send the reqeust again and observe that triggers a command injection in the python application indicating that the
insertion provider did successfully create a payload that would cause the vulnerability.
```
192.168.122.1 - - [22/Jan/2025 15:14:28] "POST /case_encode HTTP/1.1" 200 -
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   205  100   205    0     0     13      0  0:00:15  0:00:15 --:--:--    44
```
- Switch back to the Proxy tab and right click on the request to `case_noencode` and select "Add to task x" to repeat the scan against the new endpoint with the same configuration
- Observe that the command injection is found in the case where an AuditInsertionPoint is not used
