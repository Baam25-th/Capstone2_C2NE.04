from flask import Flask, request, json, jsonify
import xsscon
import sql_scanform
import re

app = Flask(__name__)


@app.route("/api/", methods=['POST','GET'])
def api():   
    data = json.dumps(request.get_json())
    matchHash = re.search(r'"hash": "(.*?)",', data).group(1)
    matchUrl = re.search(r'"url": "(.*?)"', data).group(1)
    xsscon.start(matchUrl, matchHash)
    sql_scanform.start(matchHash)
    return "Success"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port='6886')
    #app.run(debug=True)
