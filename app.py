import certifi
from flask import Flask, render_template, jsonify, request, session, redirect, url_for

app = Flask(__name__)

from pymongo import MongoClient

MONGODB_CONNECTION_STRING = "mongodb+srv://riVFerd:test_mongodb@cluster0.rq9u845.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(MONGODB_CONNECTION_STRING, tlsCAFile=certifi.where())
db = client.dbsparta

# Ini merupakan string rahasia yang perlu anda buat 
# token JWT. Anda bisa memasukkan apapun yang anda mau ke sini .
# Karena string ini disimpan di server,
# anda bisa melakukan proses encode/decode tokens hanya pada server ini.
SECRET_KEY = "SPARTA"

# Kita akan menggunakan module python untuk membutat JWT token kita
import jwt

# kita perlu module datetime untuk mengatur tanggal expired untuk token kita
import datetime

# Ketika seorang member mendaftar untuk layanan anda,
# sebaiknya anda mengenkripsi passwordnya sebelum menyimpannya di database,
# jika tidak seluruh developer anda bisa melihat (dan menggunakan)
# akun member anda
import hashlib


#################################
## HTML-related API endpoints  ##
#################################
@app.route("/")
def home():
    token_receive = request.cookies.get("mytoken")
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        user_info = db.user.find_one({"id": payload["id"]})
        return render_template("index.html", nickname=user_info["nick"])
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="Your login token has expired"))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="There was an issue logging you in"))


@app.route("/login")
def login():
    msg = request.args.get("msg")
    return render_template("login.html", msg=msg)


@app.route("/register")
def register():
    return render_template("register.html")


#################################
## Login related API endpoints ##
#################################

# [Signup API]
# Kita akan menerima data id, password, dan nickname dari
# user dan menyimpannya di MongoDb
# Sebelum menyimpan passwordnya, kita pertama-tama akan mengenkripsinya 
# menggunakan fungsi hashing SHA256  
@app.route("/api/register", methods=["POST"])
def api_register():
    id_receive = request.form["id_give"]
    pw_receive = request.form["pw_give"]
    nickname_receive = request.form["nickname_give"]

    pw_hash = hashlib.sha256(pw_receive.encode("utf-8")).hexdigest()

    db.user.insert_one({"id": id_receive, "pw": pw_hash, "nick": nickname_receive})

    return jsonify({"result": "success"})


# [Login Endpoint API]
# Kita menerima id dan password dari user,
# dan kemudian mengeluarkan sebuah token JWT untuk mereka gunakan 
@app.route("/api/login", methods=["POST"])
def api_login():
    id_receive = request.form["id_give"]
    pw_receive = request.form["pw_give"]

    # Kita akan mengenkripsi passwordnya disini dengan 
    # cara yang sama seperti user pertama kali mendaftar untuk layanan web

    pw_hash = hashlib.sha256(pw_receive.encode("utf-8")).hexdigest()

    # kita menggunakan id user dan password yang terenkripsi untuk
    # mencari user tersebut di database
    result = db.user.find_one({"id": id_receive, "pw": pw_hash})

    # Jika kita bisa menemukan user tersebut, kita membuat
    # Tokej JWT baru untuk mereka 
    if result is not None:
        # Untuk menghasilkan token JWT, kita perlu 
        # suatu "payload" dan "kunci rahasia"

        # "kunci rahasia" diperlukan untuk mendekripsi 
        # token dan melihat payload 

        # payload dibawah membawa id user dan tanggal expired token, 
        # artinya anda jika anda dekripsi tokennya, anda  
        # bisa tau id user 

        # jika kita mengatur "exp" tanggal expired, lalu suatu errror 
        # muncul ketika kita mencoba dekripsi tokennya menggunakan 
        # kunci rahasia ketika token telah expired. Ini merupakan hal bagus! 
        payload = {
            "id": id_receive,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=5),
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        # mengembalikan token ke client
        return jsonify({"result": "success", "token": token})
    # Jika kita tidak bisa menemukan user di database,
    # kita bisa menangani kasus tersebut disini 
    else:
        return jsonify({"result": "fail", "msg": "Either your email or your password is incorrect"})


# [Endpoint API verifikasi informasi user]
# Ini merupakan endpoint API yang hanya bisa
# menerima request dari user terotentikasi
# Anda hanya perlu memasukkan token yang valid
# pada request anda untuk mendapatkan akses ke
# Endpoint API ini. Sistem ini wajar karena
# beberapa informasi sebaiknya private untuk setiap user
# (contoh. shopping cart atau data akun user)
@app.route("/api/nick", methods=["GET"])
def api_valid():
    token_receive = request.cookies.get("mytoken")

    # apakah anda sudah melihat pernyataan try/catch sebelumnya?
    try:
        # kita akan coba decode tokennya dengan kunci rahasia
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        # jika tidak ada masalah, kita seharusnya melihat
        # payload terdekripsi muncul di terminal kita!
        print(payload)

        # payload terdekripsinya seharusnya berisi id user
        # kita bisa menggunakan id ini untuk mencari data user
        # dari database dan mengembalikannya ke user
        userinfo = db.user.find_one({"id": payload["id"]}, {"_id": 0})
        return jsonify({"result": "success", "nickname": userinfo["nick"]})
    except jwt.ExpiredSignatureError:
        # jika anda mencoba untuk mendekripsi token yang sudah expired
        # anda akan mendapatkan error khusus, kita menangani error nya disini
        return jsonify({"result": "fail", "msg": "Your token has expired"})
    except jwt.exceptions.DecodeError:
        # jika ada permasalahan lain ketika proses decoding,
        # kita akan tangani di sini
        return jsonify({"result": "fail", "msg": "There was an error while logging you in"})


if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)