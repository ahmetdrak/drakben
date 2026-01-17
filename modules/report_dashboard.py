# modules/report_dashboard.py
from flask import Flask, render_template
import json

app = Flask(__name__)

@app.route("/")
def dashboard():
    with open("report.json") as f:
        data = [json.loads(line) for line in f]
    return render_template("dashboard.html", reports=data)
