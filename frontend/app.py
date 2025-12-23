from flask import Flask, render_template, request, make_response, redirect
from dotenv import load_dotenv
import requests
import os

app = Flask(__name__)
load_dotenv()
backend_url = os.environ.get("BACKEND_URL")
if not backend_url:
    raise RuntimeError("BACKEND_URL not set")


def setCookie(session_id, url):
    resp = make_response(redirect(url))
    resp.set_cookie(
        "session_id",
        session_id,
        max_age=60 * 60 * 24 * 7,  # 7 days
        httponly=True,
        samesite="Lax",
        secure=False,
    )
    return resp


def deleteCookie(url):
    resp = make_response(redirect(url))
    resp.set_cookie(
        "session_id",
        "",
        max_age=0,
        expires=0,
        path="/",
        httponly=True,
        samesite="Lax",
        secure=False,
    )
    return resp


@app.route("/")
def home():
    session_id = request.cookies.get("session_id")
    if not session_id:
        return render_template("home.html", ok=False)

    try:
        response = requests.post(
            f"{backend_url}/verify",
            json={
                "session_id": session_id,
            },
            timeout=3,
        )
    except requests.RequestException:
        return render_template("home.html", ok=False)

    try:
        data = response.json()
    except ValueError:
        return render_template("home.html", ok=False)

    if data.get("success"):
        return render_template("home.html", ok=True, username=data.get("username"))

    return render_template("home.html", ok=False)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username_or_email = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    if len(username_or_email) > 20:
        return "Length of username too long, try again"
    elif len(username_or_email) < 5:
        return "Length of username too short, try again"

    if len(password) > 255:
        return "Length of password too long, try again"
    elif len(password) < 5:
        return "Length of password too short, try again"

    try:
        response = requests.post(
            f"{backend_url}/login",
            json={
                "username_or_email": username_or_email,
                "password": password,
            },
            timeout=3,
        )
    except requests.RequestException:
        return render_template("login.html")

    try:
        data = response.json()
    except ValueError:
        return render_template("login.html")

    if data.get("success"):
        return setCookie(data.get("session_id"), "/")
    else:
        return f"Login unsuccesful\n {data.get("message")}"


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    email = (request.form.get("email") or "").strip()

    if len(username) > 20:
        return "Length of username too long, try again"

    if len(password) > 255:
        return "Length of password too long, try again"

    try:
        response = requests.post(
            f"{backend_url}/signup",
            json={"username": username, "password": password, "email": email},
            timeout=3,
        )
    except requests.RequestException:
        return render_template("signup.html")

    try:
        data = response.json()
    except ValueError:
        return render_template("signup.html")

    if data.get("success"):
        return setCookie(data.get("session_id"), "/")
    else:
        return f"Signup unsuccesful\n {data.get("message")}"


@app.route("/logout", methods=["GET"])
def logout():
    session_id = request.cookies.get("session_id")
    if not session_id:
        return "Not currently logged in"

    try:
        response = requests.post(
            f"{backend_url}/logout",
            json={"session_id": session_id},
            timeout=3,
        )
    except requests.RequestException:
        return "Internal database error, try again."

    try:
        data = response.json()
    except ValueError:
        return "Internal database error, try again."

    if data.get("success"):
        return deleteCookie("/")


if __name__ == "__main__":
    app.run(debug=True)
