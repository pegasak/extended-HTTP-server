from flask import Flask, redirect, url_for, render_template, request, session, flash, jsonify
from datetime import timedelta, datetime
from flask_sqlalchemy import SQLAlchemy
import jwt
import uuid
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')  # Секретный ключ
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///default.db')  # URI для базы данных
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(minutes=5)

db = SQLAlchemy(app)

# Таблица пользователей
class users(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))

    def __init__(self, name, email):
        self.name = name
        self.email = email


# Таблица использованных токенов (защита от Replay Attack)
class used_tokens(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    jti = db.Column(db.String(100), unique=True)


# Инициализация базы данных
with app.app_context():
    db.create_all()


# Функция генерации токенов
def create_token(username, exp_minutes, is_refresh=False):
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=exp_minutes),
        "jti": str(uuid.uuid4()),  # Уникальный идентификатор токена
        "type": "refresh" if is_refresh else "access"
    }
    return jwt.encode(payload, app.secret_key, algorithm="HS256")


@app.route("/")
def home():
    return render_template("index.html")


# Эндпоинт для авторизации
@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        user = request.form["nm"]
        found_user = users.query.filter_by(name=user).first()

        if found_user:
            # Генерация токенов
            access_token = create_token(user, 5)  # Живёт 5 минут
            refresh_token = create_token(user, 1440, is_refresh=True)  # Живёт 24 часа
            return jsonify({"access_token": access_token, "refresh_token": refresh_token})
        else:
            flash("User not found!")
            return redirect(url_for("login"))
    return render_template("login.html")


# Эндпоинт для защищённого ресурса
@app.route("/protected", methods=["GET"])
def protected():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header missing or invalid"}), 401

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])

        # Проверка на повторное использование токена
        jti = payload["jti"]
        if used_tokens.query.filter_by(jti=jti).first():
            return jsonify({"error": "Token already used"}), 401

        # Пометка токена как использованного
        new_token = used_tokens(jti=jti)
        db.session.add(new_token)
        db.session.commit()

        return jsonify({"message": f"Hello, {payload['sub']}!"})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


# Эндпоинт для обновления токена
@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.json
    refresh_token = data.get("refresh_token")

    try:
        payload = jwt.decode(refresh_token, app.secret_key, algorithms=["HS256"])
        if payload["type"] != "refresh":
            return jsonify({"error": "Invalid token type"}), 401

        # Генерация нового access токена
        new_access_token = create_token(payload["sub"], 5)
        return jsonify({"access_token": new_access_token})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


# Эндпоинт для регистрации пользователя
@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        username = request.form["nm"]
        email = request.form["email"]
        found_user = users.query.filter_by(name=username).first()

        if found_user:
            flash("User already exists!")
            return redirect(url_for("register"))

        new_user = users(name=username, email=email)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/view")
def view():
    return render_template("view.html", values=users.query.all())


if __name__ == "__main__":
    app.run(debug=True)
