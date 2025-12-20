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
    
    username_or_email = request.form.get("username").strip()
    password = request.form.get("password").strip()
    
    if len(username_or_email) > 20: 
        return "Length of username too long, try again"
    
    if len(password) > 255: 
        return "Length of password too long, try again"
    
    response = requests.post(
        "http://127.0.0.1:3000/login",
        json={
            "username_or_email": username_or_email,
            "password": password,
        }
    ).json()
    
    if response.get("success"): 
        return "Login Succesful"
    else: 
        return f"Login unsuccesful {response.get("message")}"
    
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    
    username = request.form.get("username").strip()
    password = request.form.get("password").strip()
    email = request.form.get("email").strip()
    
    if len(username) > 20 :
        return "Length of username too long, try again"
    
    if len(password) > 255 :
        return "Length of password too long, try again"
    
    response = requests.post(
        "http://127.0.0.1:3000/signup",
        json = {
            "username": username,
            "password": password,
            "email": email
        }
    ).json()
    
    if response.get("success"):
        return "Signup Succesful"
    else:
        return f"Signup unsuccesful {response.get("message")}"

if __name__ == "__main__":
    app.run(debug=True)
