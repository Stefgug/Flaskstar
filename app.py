from flask import Flask, render_template, request # Add render_template here
import requests

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/portfolio")
def portfolio():
    return render_template("portfolio.html")


@app.route("/portfolio/RAGstar")
@app.route("/ragstar")
def ragstar():
    return render_template("ragstar.html")
