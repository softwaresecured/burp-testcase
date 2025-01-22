# testcase for issue 92
# 2 endpoints, both have an arg1 parameter that is vulnerable to command injection
# /case_noencode does not have any encoding
# /case_encode is URL encoded and base64 encoded
# Curl commands to send request through proxy:
# curl -x localhost:8080 -X POST http://localhost:4444/case_encode -d 'arg1=hostname' -H 'Content-Type: application/x-www-form-urlencoded'
# curl -x localhost:8080 -X POST http://localhost:4444/case_noencode -d 'arg1=%59%47%46%6a%4c%6a%45%74%63%33%4d%75%62%44%5a%33%61%54%46%6c%4f%48%46%6f%61%33%46%35%64%6a%4e%69%61%6a%56%6b%5a%54%64%70%4e%6e%6c%6c%61%57%6c%6a%64%47%5a%6d%5a%7a%51%77%4e%69%42%73%63%6e%56%6a%59%41%3d%3d' -H 'Content-Type: application/x-www-form-urlencoded'

import subprocess
import os
import base64
from flask import Flask, make_response, request, abort

app = Flask(__name__)

# Accepts a parameter called "arg1" and base64 decodes it and then reverses it. The result is passed into a shell
# command. The audit insertion point will provide a base64/reversed payload
@app.route("/case_encode", methods=['POST'])
def case_encode():
    result = subprocess.run(['bash', '-c',base64.b64decode(request.form.get("arg1"))[::-1]], stdout=subprocess.PIPE)
    output = result.stdout.decode("utf-8")
    response = make_response(output,200)
    return response

# Passes a parameter in the body called "arg1" directly into a shell command
@app.route("/case_noencode", methods=['POST'])
def case_noencode():
    result = subprocess.run(['bash', '-c',request.form.get("arg1")], stdout=subprocess.PIPE)
    output = result.stdout.decode("utf-8")
    response = make_response(output,200)
    return response

if __name__ == '__main__':
      app.run(host='0.0.0.0', port=4444)
