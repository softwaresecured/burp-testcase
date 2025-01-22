"""
# Testcase for AuditInsertionPoint issue

# 2 endpoints, both have an arg1 parameter that is vulnerable to command injection
- /case_noencode does not have any encoding
- /case_encode is URL encoded and base64 encoded and reversed
    - The base64 reverse combination will not be picked up by the scanner by default and requires an AuditInsertionPoint

Curl commands to send request through proxy:
curl -x localhost:8080 -X POST http://localhost:4444/case_noencode -d 'arg1=hostname' -H 'Content-Type: application/x-www-form-urlencoded'
curl -x localhost:8080 -X POST http://localhost:4444/case_encode -d 'arg1=%5a%57%31%68%62%6e%52%7a%62%32%67%3d' -H 'Content-Type: application/x-www-form-urlencoded'

Note: For windows replace sh -c with cmd.exe /c in the subprocess.run
"""
import subprocess
import os
import base64
from flask import Flask, make_response, request, abort

app = Flask(__name__)

# Accepts a parameter called "arg1" and base64 decodes it and then reverses it. The result is passed into a shell
# command. The audit insertion point will provide a base64/reversed payload
@app.route("/case_encode", methods=['POST'])
def case_encode():
    result = subprocess.run(['sh', '-c',base64.b64decode(request.form.get("arg1"))[::-1]], stdout=subprocess.PIPE)
    output = result.stdout.decode("utf-8")
    response = make_response(output,200)
    return response

# Passes a parameter in the body called "arg1" directly into a shell command
@app.route("/case_noencode", methods=['POST'])
def case_noencode():
    result = subprocess.run(['sh', '-c',request.form.get("arg1")], stdout=subprocess.PIPE)
    output = result.stdout.decode("utf-8")
    response = make_response(output,200)
    return response

if __name__ == '__main__':
      app.run(host='0.0.0.0', port=4444)
