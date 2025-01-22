# testcase for issue 92
# 2 endpoints, both have an arg1 parameter that is vulnerable to command injection
# /case_noencode does not have any encoding
# /case_encode is URL encoded and base64 encoded and reversed ( the plugin tests this specifically )
# Curl commands to send request through proxy:
# curl -x localhost:8080 -X POST http://localhost:4444/case_encode -d 'arg1=hostname' -H 'Content-Type: application/x-www-form-urlencoded'
# curl -x localhost:8080 -X POST http://localhost:4444/case_noencode -d 'arg1=%61%47%39%7a%64%47%35%68%62%57%55%3d' -H 'Content-Type: application/x-www-form-urlencoded'

import subprocess
import os
import base64
from flask import Flask, make_response, request, abort

app = Flask(__name__)

@app.route("/case_encode", methods=['POST'])
def case_encode():
    result = subprocess.run(['bash', '-c',base64.b64decode(request.form.get("arg1"))[::-1]], stdout=subprocess.PIPE)
    output = result.stdout.decode("utf-8")
    response = make_response(output,200)
    return response

@app.route("/case_noencode", methods=['POST'])
def case_noencode():
    result = subprocess.run(['bash', '-c',request.form.get("arg1")], stdout=subprocess.PIPE)
    output = result.stdout.decode("utf-8")
    response = make_response(output,200)
    return response

if __name__ == '__main__':
      app.run(host='0.0.0.0', port=4444)
