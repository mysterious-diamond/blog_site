from flask import Flask, render_template, request
import requests

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    
    username = request.form.get("username")
    password = request.form.get("password")
    
    response = requests.post(
        "http://127.0.0.1:3000/login",
        json={
            "username": username,
            "password": password,
        }
    ).json()
    
    if response.get("success") : return "Login Succesful"
    else : return "Login Unsuccesful"

if __name__ == "__main__":
    app.run(debug=True)
