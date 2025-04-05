from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify
from flask_mysqldb import MySQL
from forms import Signup_app, Signup_account, Payment, Login, CheckBalance, ProfilePicForm
import bcrypt 
from flask_bcrypt import Bcrypt
from flask_session import Session
from werkzeug.utils import secure_filename
import os
import time
from PIL import Image, ImageDraw, ImageFont
import random
import io
import base64
from tensorflow.keras.models import load_model

import numpy as np
from tensorflow.keras.preprocessing.image import load_img, img_to_array

from flask_wtf import CSRFProtect


# Charger le modèle de reconnaissance d'empreinte digitales déjà entrainé 
model = load_model('./models/biometrie.h5')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'une_cle_secrete'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
Session(app)
csrf = CSRFProtect(app)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'corine'
app.config['MYSQL_PASSWORD'] = 'corine03'
app.config['MYSQL_DB'] = 'biometriesystem'

mysql = MySQL(app)

bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

from flask import Flask, render_template, request, flash, session
from flask_bcrypt import Bcrypt
from forms import Signup_app, Login
from wtforms.validators import ValidationError


# Vérification de la force du mot de passe
def check_password_strength(password):
    """Function to check password strength according to specific criteria."""
    import re
    if len(password) < 8:
        return False, 'Password must be at least 8 characters long.'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter.'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter.'
    if not re.search(r'\d', password):
        return False, 'Password must contain at least one digit.'
    if not re.search(r'[@$!%*?&]', password):
        return False, 'Password must contain at least one special character.'
    return True, ''


from PIL import Image, ImageDraw, ImageFont
import os

def generate_profile_pic(username):
    # Obtenir les initiales (la première lettre du nom d'utilisateur en majuscule)
    initial = username[0].upper()

    # Définir la taille de l'image, la couleur de fond et la couleur du texte
    img_size = (128, 128)
    img_color = (73, 109, 137)
    text_color = (255, 255, 255)
    font_size = 1000  # Taille de la police (assez grande pour remplir l'image)

    # Créer une image vide
    img = Image.new('RGB', img_size, color=img_color)
    d = ImageDraw.Draw(img)

    # Charger une police
    try:
        font = ImageFont.truetype("arial.ttf", font_size)
    except IOError:
        font = ImageFont.load_default()

    # Obtenir la taille du texte pour le centrer
    text_width, text_height = d.textsize(initial, font=font)
    position = ((img_size[0] - text_width) / 2, (img_size[1] - text_height) / 2)

    # Ajouter le texte à l'image
    d.text(position, initial, fill=text_color, font=font)

    # Enregistrer l'image
    filename = f"{username}_profile.png"
    filepath = os.path.join('static/uploads', filename)
    img.save(filepath)

    return filename



@app.route("/", methods=['GET', 'POST'])
def index():
    login_form = Login()
    signup_form = Signup_app()
    password_valid = False
    data_send = False
    
    if request.method == 'POST':
        password = request.form.get('password')
        password_valid, password_error = check_password_strength(password)
        if signup_form.validate_on_submit():
            lastname = request.form.get('lastname')
            firstname = request.form.get('firstname')
            birthday = request.form.get('birthday')
            email = request.form.get('email')
            username = request.form.get('username')
            
            # Check password strength
            password_valid, password_error = check_password_strength(password)
            if not password_valid:
                flash(password_error, 'danger')
                return render_template("index.html", password_error=password_error, signup_form=signup_form, login_form=login_form, password_valid=False)

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            password = hashed_password
            
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT username, email FROM users WHERE username = %s OR email=%s", (username, email,))
            existing_account = cursor.fetchone()
            if existing_account:
                exist = True
                data_send = False
                return render_template("index.html", exist=exist, data_send=data_send, signup_form=signup_form, login_form=login_form)
            elif not existing_account and password_valid:
                data_send = True
                
                # Générer une photo de profil par défaut avec les initiales
                profile_pic = generate_profile_pic(username)
                
                cursor.execute("INSERT INTO users (lastname, firstname, birthday, email, username, password, profile_pic) VALUES (%s,%s, %s, %s, %s, %s, %s)", 
                               (lastname, firstname, birthday, email, username, password, profile_pic))
                mysql.connection.commit()
                cursor.execute("SELECT id_user FROM users WHERE username = %s AND password = %s", (username, password))
                id_user = cursor.fetchone()
                session['id_user'] = id_user[0]
                session['username'] = username
                session['profile_pic'] = profile_pic  # Définir la photo de profil par défaut dans la session
                cursor.close()
                return render_template('index.html', data_send=data_send, exist=False, signup_form=signup_form, login_form=login_form)
        else:
            return render_template("index.html",password_error=password_error, data_send=data_send, password_valid=password_valid, signup_form=signup_form, login_form=login_form)
    elif request.method == 'GET':
        return render_template("index.html", signup_form=signup_form, login_form=login_form)



@app.route("/actions", methods=['POST', 'GET'])
def login():
    login_form = Login()
    signup_account_form = Signup_account()
    payment_form = Payment()
    signup_form = Signup_app()
    checkBalance_form = CheckBalance()
    profilForm = ProfilePicForm()

    if 'username' in session:
        username = session['username']
        connexion = True
    else:
        username = None
        connexion = False

    if request.method == 'POST':
        login_data = request.form
        username_input = login_data.get('username')
        password = login_data.get('password')
        cursor = mysql.connection.cursor()

        cursor.execute("SELECT id_user, password, profile_pic FROM users WHERE username = %s", (username_input,))
        user = cursor.fetchone()
        
        if user is not None:
            id_user, stored_password, profile_pic = user
            if bcrypt.check_password_hash(stored_password, password):
                session['id_user'] = id_user
                session['username'] = username_input
                session['profile_pic'] = profile_pic if profile_pic else 'images/welcome_back.png'
                
                cursor.execute(
                    "SELECT DISTINCT id_payment, payment_date, payment_time, historical.amount, account_number_sender, account_number_beneficiary, username, name_card, payment_reason, payment_status "
                    "FROM historical, users, account "
                    "WHERE %s=historical.id_user AND account.account_number=historical.account_number_sender AND username=%s", 
                    (id_user, username_input)
                )
                transactions = cursor.fetchall()
                cursor.close()
                
                flash('Connexion réussie !', 'success')
                return render_template(
                    "actions.html",
                    time=time,
                    profilForm=profilForm,
                    transactions=transactions,
                    checkBalance_form=checkBalance_form,
                    signup_account_form=signup_account_form,
                    payment_form=payment_form,
                    username=username_input,
                    connexion=True,
                    profile_pic=session['profile_pic']
                )
            else:
                flash('Invalid username or password. Please try again or create an account if you do not have one.', 'danger')
                cursor.close()
                return render_template("index.html", login_form=login_form, signup_form=signup_form, connexion=False)
        else:
            flash('Invalid username or password. Please try again or create an account if you do not have one.', 'danger')
            cursor.close()
            return render_template("index.html", login_form=login_form, signup_form=signup_form, connexion=False)

    elif session.get('id_user') is not None and request.method == 'GET':
        cursor = mysql.connection.cursor()
        cursor.execute(
            "SELECT DISTINCT id_payment, payment_date, payment_time, historical.amount, account_number_sender, account_number_beneficiary, username, name_card, payment_reason, payment_status "
            "FROM historical, users, account "
            "WHERE %s=historical.id_user AND account.account_number=historical.account_number_sender AND username=%s", 
            (session.get('id_user'), session.get('username'))
        )
        transactions = cursor.fetchall()
        cursor.close()

        return render_template(
            "actions.html",
            time=time,
            profilForm=profilForm,
            transactions=transactions,
            checkBalance_form=checkBalance_form,
            payment_form=payment_form,
            signup_account_form=signup_account_form,
            username=username,
            connexion=connexion,
            profile_pic=session.get('profile_pic', 'images/welcome_back.png')
        )
    else:
        flash('Invalid username or password. Please try again or create an account if you do not have one.', 'danger')
        return render_template("index.html", login_form=login_form, signup_form=signup_form, connexion=False)



@app.route("/logout", methods=['POST', 'GET'])
def logout():
    if "id_user" in session:
        session.pop("id_user")
        if request.method == 'POST':
            return jsonify({"success": True}), 200
        else:
            return redirect(url_for('index'))
    return redirect(url_for('index'))


# Formulaire pour créer un compte bancaire 

bcrypt = Bcrypt(app)

@app.route("/payment_account", methods=['POST', 'GET'])
def payment_account_form():
    signup_account_form = Signup_account()
    payment_form = Payment()
    checkBalance_form = CheckBalance()
    login_form = Login()
    signup_form = Signup_app()
    profilForm = ProfilePicForm()

    # Initialisation des variables
    username = session.get('username')
    id_user = session.get('id_user')
    connexion_payment_form = bool(username)
    exist = False
    data_send = False
    valid_account_number = True
    amount = 0

    cursor = mysql.connection.cursor()
    cursor.execute("""
            SELECT id_payment, payment_date, payment_time, historical.amount, 
                   account_number_sender, account_number_beneficiary, username, 
                   name_card, payment_reason, payment_status 
            FROM historical, users, account 
            WHERE %s = historical.id_user 
              AND account.account_number = historical.account_number_sender 
              AND username = %s
        """, (id_user, username))
    transactions = cursor.fetchall()
    
    if id_user:
        cursor.execute("SELECT amount FROM account WHERE id_user = %s", (id_user,))
        result = cursor.fetchone()
        amount = result[0] if result else 0

    if request.method == 'POST' and signup_account_form.validate_on_submit():
        account_number = signup_account_form.account_number.data
        name_card = signup_account_form.name_card.data
        cvv = signup_account_form.cvv.data
        amount = signup_account_form.amount.data
        fingerPrint = signup_account_form.fingerPrint.data
        pin_code = signup_account_form.pin_code.data
        hashed_pin_code = bcrypt.generate_password_hash(pin_code).decode('utf-8')

        cursor.execute("SELECT account_number FROM account WHERE account_number = %s", (account_number,))
        existing_account = cursor.fetchone()

        if existing_account:
            exist = True
            flash("Le numéro de compte existe déjà. Veuillez en choisir un autre.", "danger")
            print("Numéro de compte existe déjà")
            return render_template("actions.html",time=time,profile_pic=session['profile_pic'], profilForm=profilForm, valid_account_number=valid_account_number, exist=exist, signup_account_form=signup_account_form, payment_form=payment_form, checkBalance_form=checkBalance_form, login_form=login_form)
        
        # Validité de la taille du numéro de compte bancaire 
        elif (len(account_number) not in [4,10]):
            valid_account_number = False
            return render_template("actions.html",time=time,profile_pic=session['profile_pic'], profilForm=profilForm, valid_account_number=valid_account_number, signup_account_form=signup_account_form, payment_form=payment_form, checkBalance_form=checkBalance_form, login_form=login_form)

        else:
            cursor.execute("""
                INSERT INTO account (account_number, name_card, cvv, amount, pin_code, id_user) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (account_number, name_card, cvv, amount, hashed_pin_code, id_user))
            mysql.connection.commit()


            data_send = True
            exist = False
            flash("Compte créé avec succès!", "success")
            print("compte crée avec succès")
            return render_template("actions.html",username=username,time=time,profile_pic=session['profile_pic'], profilForm=profilForm, data_send=data_send, valid_account_number=valid_account_number, signup_account_form=signup_account_form, payment_form=payment_form, checkBalance_form=checkBalance_form, login_form=login_form)

    elif id_user is not None and request.method == "GET":
        return render_template("actions.html",time=time,profile_pic=session['profile_pic'], profilForm=profilForm,
                           checkBalance_form=checkBalance_form, 
                           amount=amount, 
                           signup_account_form=signup_account_form, 
                           payment_form=payment_form, 
                           username=username, 
                           transactions=transactions, 
                           connexion_payment_form=connexion_payment_form)

    else:
        flash('Vous devez être connecté pour accéder à cette page.', 'danger')
        return render_template("index.html", login_form=login_form, signup_form=signup_form, connexion=False)

    
# Vérification de l'empreinte digitale
import base64
import os
from werkzeug.utils import secure_filename

# Charger votre modèle ici
model = load_model('./models/biometrie.h5')

@app.route("/payment", methods=['POST', 'GET'])
def payment():
    print("Payment function called")  # Début de la fonction payment

    checkBalance_form = CheckBalance()
    signup_account_form = Signup_account()
    payment_form = Payment()
    login_form = Login()
    signup_form = Signup_app()

    if 'username' in session:
        username = session['username']
        id_user = session.get('id_user')
    else:
        username = None
        id_user = None
        return render_template("index.html", signup_form=signup_form, login_form=login_form, connexion=False)

    # Initialiser les variables pour gérer les messages d'erreur
    account_not_found = False
    beneficiary_account_not_found = False
    invalid_credentials = False
    insufficient_balance = False
    payment_status = False
    verify_finger = False
    fingerprint_error = False
    profilForm = ProfilePicForm()

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id_payment, payment_date, payment_time, historical.amount, account_number_sender, account_number_beneficiary, username, name_card, payment_reason, payment_status FROM historical, users, account WHERE %s=historical.id_user AND account.account_number=historical.account_number_sender AND username=%s", (session.get('id_user'), session.get('username'),))
    transactions = cursor.fetchall()

    if request.method == 'POST':
        print("POST method detected")  # Vérification de la méthode POST
        if payment_form.validate_on_submit():
            account_number_sender = payment_form.account_number_sender.data
            account_number_beneficiary = payment_form.account_number_beneficiary.data
            cvv = str(payment_form.cvv.data).strip()
            pin_code = payment_form.pin_code.data
            reason_payment = payment_form.reason_payment.data
            amount_be_paid_str = request.form.get('amount_be_paid')
            if not amount_be_paid_str:  # Vérifie si la chaîne est vide
                amount_be_paid = 0  # Valeur par défaut
            else:
                try:
                    amount_be_paid = float(amount_be_paid_str)
                except ValueError:
                    amount_be_paid = 0  # Valeur par défaut ou autre action selon votre logique
    

            print(f"Account sender: {account_number_sender}, Account beneficiary: {account_number_beneficiary}, Amount: {amount_be_paid}, CVV: {cvv}, PIN: {pin_code}, Reason: {reason_payment}")

            # Rechercher les informations du compte de l'expéditeur
            cursor.execute("SELECT * FROM account WHERE account_number = %s", (account_number_sender,))
            account_data_sender = cursor.fetchone()
            print(f"Sender account data: {account_data_sender}")

            # Rechercher les informations du compte du bénéficiaire
            cursor.execute("SELECT * FROM account WHERE account_number = %s", (account_number_beneficiary,))
            account_data_beneficiary = cursor.fetchone()
            print(f"Beneficiary account data: {account_data_beneficiary}")

            if account_data_sender is not None:
                print("Sender account found")
                # Récupérer le CVV et le code PIN associés au compte de l'expéditeur
                cvv_saved = str(account_data_sender[3]).strip()
                saved_pin_code = account_data_sender[5]

                # Vérifier la correspondance de l'utilisateur connecté, le CVV et le code PIN fourni
                if account_data_sender[6] == session.get('id_user') and cvv == cvv_saved and bcrypt.check_password_hash(saved_pin_code, pin_code):
                    print("Credentials verified")
                    invalid_credentials = False
                    # Vérification d'empreinte digitale
                    fingerprint_image = request.files.get('fingerprint_image')
                    if fingerprint_image:
                        print("Fingerprint image found")
                        # Créez le répertoire si nécessaire
                        upload_folder = 'static/uploads'
                        if not os.path.exists(upload_folder):
                            os.makedirs(upload_folder)
                        
                        filename = secure_filename(fingerprint_image.filename)
                        filepath = os.path.join(upload_folder, filename)
                        fingerprint_image.save(filepath)
                        
                        if not os.path.exists(filepath):
                            flash('File not saved correctly. Please try again.', 'danger')
                            return redirect(url_for('payment'))
                    
                        is_verified, predicted_probabilities = verify_fingerprint(filepath, current_username=session.get('username'), model=model)
                        print(f"is_verified: {is_verified}, predicted_probabilities: {predicted_probabilities}")

                        if not is_verified:
                            flash('Fingerprint verification failed. Please try again.', 'danger')
                            fingerprint_error = True
                            os.remove(filepath)  # Supprimez le fichier après vérification
                            return render_template("actions.html",time=time,profile_pic=session['profile_pic'],profilForm=profilForm, transactions=transactions, checkBalance_form=checkBalance_form, username=session.get('username'), signup_account_form=signup_account_form, payment_form=payment_form, account_not_found=account_not_found, beneficiary_account_not_found=beneficiary_account_not_found, invalid_credentials=invalid_credentials, insufficient_balance=insufficient_balance, verify_finger=verify_finger, fingerprint_error=fingerprint_error)
                        
                        elif is_verified:
                            verify_finger = True
                        # Supprimez le fichier après la vérification
                        if os.path.exists(filepath):
                            os.remove(filepath)
                        else:
                            flash('File not found during deletion. Please check the system.', 'danger')
                    
                    # Effectuer le paiement si l'utilisateur courant, le CVV, le code PIN et l'empreinte digitale correspondent
                    current_amount_sender = account_data_sender[4]
                    new_amount_sender = current_amount_sender - amount_be_paid

                    if new_amount_sender >= 0:
                        print("Sufficient balance")
                        # Vérifier si le compte bénéficiaire existe
                        if account_data_beneficiary is not None:
                            current_amount_beneficiary = account_data_beneficiary[4]
                            
                            # Si current_amount_beneficiary est None, initialisez-le à 0
                            if current_amount_beneficiary is None:
                                current_amount_beneficiary = 0

                            new_amount_beneficiary = current_amount_beneficiary + amount_be_paid
                            payment_status = True

                            # Mettre à jour le solde de l'expéditeur
                            cursor.execute("UPDATE account SET amount = %s WHERE account_number = %s", (new_amount_sender, account_number_sender,))
                            
                            # Mettre à jour le solde du bénéficiaire
                            cursor.execute("UPDATE account SET amount = %s WHERE account_number = %s", (new_amount_beneficiary, account_number_beneficiary,))
                            
                            # Insérer les données de paiement dans la table historique 
                            cursor.execute("INSERT INTO historical (id_user, payment_date, payment_time, amount, account_number_sender, account_number_beneficiary, payment_status, payment_reason) VALUES (%s, CURDATE(), CURTIME(), %s, %s, %s, %s, %s)", 
                                        (session.get('id_user'), amount_be_paid, account_number_sender, account_number_beneficiary, payment_status, reason_payment))
                            
                            mysql.connection.commit()
                            print("Payment successful")
                            return render_template("actions.html",profile_pic=session['profile_pic'],time=time,profilForm=profilForm, transactions=transactions, checkBalance_form=checkBalance_form, username=session.get('username'), signup_account_form=signup_account_form, payment_form=payment_form, account_not_found=account_not_found, beneficiary_account_not_found=beneficiary_account_not_found, invalid_credentials=invalid_credentials, insufficient_balance=insufficient_balance, verify_finger=verify_finger, fingerprint_error=fingerprint_error)
                        else:
                            beneficiary_account_not_found = True
                            print("Beneficiary account not found")
                    else:
                        insufficient_balance = True
                        print("Insufficient balance")
                else:
                    invalid_credentials = True
                    print("Invalid credentials")
            else:
                account_not_found = True
                print("Account not found")

            cursor.close()
            return render_template("actions.html",profile_pic=session['profile_pic'],time=time,profilForm=profilForm, transactions=transactions, checkBalance_form=checkBalance_form, username=session.get('username'), signup_account_form=signup_account_form, payment_form=payment_form, account_not_found=account_not_found, beneficiary_account_not_found=beneficiary_account_not_found, invalid_credentials=invalid_credentials, insufficient_balance=insufficient_balance, verify_finger=verify_finger, fingerprint_error=fingerprint_error, data_send=True)
        else:
            return render_template("actions.html",profile_pic=session['profile_pic'],time=time,profilForm=profilForm, transactions=transactions, checkBalance_form=checkBalance_form, username=session.get('username'), signup_account_form=signup_account_form, payment_form=payment_form, account_not_found=account_not_found, beneficiary_account_not_found=beneficiary_account_not_found, invalid_credentials=invalid_credentials, insufficient_balance=insufficient_balance, verify_finger=verify_finger, fingerprint_error=fingerprint_error, data_send=False)
    elif id_user is not None and request.method == "GET":
        return render_template("actions.html",profile_pic=session['profile_pic'], time=time, profilForm=profilForm, transactions=transactions, checkBalance_form=checkBalance_form, username=session.get('username'), signup_account_form=signup_account_form, payment_form=payment_form)
    else:
        flash('You must be logged in to access this page.', 'danger')
        return render_template("index.html", login_form=login_form, signup_form=signup_form, connexion=False)


# Prétraitement de l'image
def preprocess_image(image_path):
    img_height, img_width = 128, 128  # Taille des images après redimensionnement
    img = load_img(image_path, target_size=(img_height, img_width))
    img_array = img_to_array(img)
    img_array = np.expand_dims(img_array, axis=0)
    img_array /= 255.0  # Normalise les valeurs des pixels
    return img_array

# Vérification avec notre modèle
def verify_fingerprint(image_path, current_username, model, threshold=0.8):
    print(f"Verifying fingerprint for {current_username} with image {image_path}")  # Début de la fonction de vérification
    preprocessed_image = preprocess_image(image_path)
    predictions = model.predict(preprocessed_image)
    predicted_probabilities = np.max(predictions, axis=1)
    predicted_class = np.argmax(predictions, axis=1)[0]  # Récupère la classe prédite

    # Créez votre dictionnaire de mappage ici ou chargez-le depuis une configuration
    class_to_username = {0: 'Coco@Vega',1: 'Fofie',2: 'Harold',3: 'Kum',4: 'Lissouck',5: 'Marah',6: 'Ngessi',7: 'Nyemb'}

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT firstname, lastname FROM users WHERE id_user = %s", (session.get('id_user'),))
    user_data = cursor.fetchone()
    firstname = user_data[0]
    lastname = user_data[1]
    print(f"Firstname: {firstname}, Lastname: {lastname}, ID User: {session.get('id_user')}")
                                  
    # Vérification des correspondances de prénom, nom d'utilisateur ou nom de famille
    if any(name.upper() in (firstname.upper(), lastname.upper(), session.get('username').upper()) for name in class_to_username.values()):
        current_user = True
    else:
        current_user = False
    
    # Obtenir le nom d'utilisateur prédit
    predicted_username = class_to_username.get(predicted_class)

    # Convertir les noms en majuscules pour éviter la sensibilité à la casse
    predicted_username_upper = predicted_username.upper() if predicted_username else None
    current_username_upper = current_username.upper()

    print(f"Predicted username: {predicted_username_upper}, Current username: {current_username_upper}, Probability: {predicted_probabilities}")

    # Vérifiez si le nom d'utilisateur prédit correspond au nom d'utilisateur actuel avec une probabilité suffisante
    if (predicted_username_upper == current_username_upper) and predicted_probabilities >= threshold:
        return True, predicted_probabilities
    else:
        return False, predicted_probabilities



@app.route('/account_balance', methods=['GET', 'POST'])
def balance():
    cursor = mysql.connection.cursor()
    signup_account_form = Signup_account()
    payment_form = Payment()
    login_form = Login()
    signup_form = Signup_app()
    profilForm = ProfilePicForm()
    username = session.get('username')
    cursor.execute("SELECT id_payment, payment_date, payment_time, historical.amount, account_number_sender, account_number_beneficiary, username, name_card, payment_reason, payment_status FROM historical, users, account WHERE %s=historical.id_user AND account.account_number=historical.account_number_sender AND username=%s", (session.get('id_user'),session.get('username'),))
    transactions = cursor.fetchall()

    if 'username' in session:
        username = session['username']
        id_user = session.get('id_user')
    else:
        username = None
        id_user = None

    checkBalance_form = CheckBalance()
    if request.method == 'POST' and checkBalance_form.validate_on_submit():
        account_number = request.form.get('account_number')
        pin_code = request.form.get('pin_code')  # Récupérer le code PIN fourni par l'utilisateur
        session['account_number'] = account_number

        # Vérifier si le numéro de compte existe dans la base de données
        cursor.execute("SELECT amount, pin_code FROM account, users WHERE account.id_user = users.id_user AND account_number=%s", (session.get('account_number'),))
        account_data = cursor.fetchone()

        if account_data:
            # Si le numéro de compte existe, récupérer le solde et le code PIN
            amount = account_data[0]
            saved_pin_code = account_data[1]  # Récupérer le code PIN stocké dans la base de données

            # Vérifier si le code PIN fourni correspond au code PIN stocké dans la base de données
            if bcrypt.check_password_hash(saved_pin_code, pin_code):
                # Afficher le solde si le code PIN est correct
                return render_template("actions.html",profile_pic=session['profile_pic'],time=time, profilForm=profilForm, transactions=transactions, username=username, payment_form=payment_form, signup_account_form=signup_account_form, amount=amount, checkBalance_form=checkBalance_form, check=True)
            else:
                # Afficher un message d'erreur si le code PIN est incorrect
                error_message_check_balance = 'Invalid PIN code or invalid account number. Please enter the correct informations.'
                return render_template("actions.html",profilForm=profilForm, profile_pic=session['profile_pic'], time=time, transactions=transactions, error_message_check_balance=error_message_check_balance, username=username, payment_form=payment_form, signup_account_form=signup_account_form, checkBalance_form=checkBalance_form, nocheck=True)
        else:
            # Afficher un message d'erreur si le numéro de compte n'existe pas
            flash('The specified account number does not exist. Please enter a valid account number.', 'danger')
            return render_template("actions.html",profile_pic=session['profile_pic'], profilForm=profilForm, time=time, transactions=transactions, username=username, payment_form=payment_form, signup_account_form=signup_account_form, checkBalance_form=checkBalance_form, nocheck=True)
    elif id_user is not None and request.method == "GET":
        return render_template("actions.html",profile_pic=session['profile_pic'], time=time,profilForm=profilForm, transactions=transactions, checkBalance_form=checkBalance_form, signup_account_form=signup_account_form, payment_form=payment_form, username=username)
    else:
        flash('You must be logged in to access this page.', 'danger')
        return render_template("index.html", login_form=login_form, signup_form=signup_form, connexion=False)


from werkzeug.utils import secure_filename
import os
from flask import session, redirect, url_for, flash, render_template, request
import time

@app.route('/update_profile_pic', methods=['POST', 'GET'])
def update_profile_pic():
    signup_account_form = Signup_account()
    payment_form = Payment()
    checkBalance_form = CheckBalance()
    profilForm = ProfilePicForm()
    login_form = Login()
    signup_form = Signup_app()
    id_user = session.get('id_user')
    
    if not id_user:
        flash('You must be logged in to access this page.', 'danger')
        return render_template("index.html", login_form=login_form, signup_form=signup_form, connexion=False)

    
    cursor = mysql.connection.cursor()

    if request.method == 'POST' and profilForm.validate_on_submit():
        profile_pic = profilForm.profile_pic.data
        filename = secure_filename(profile_pic.filename)
        filepath = os.path.join('static/uploads', filename)

        # Save the file
        profile_pic.save(filepath)

        # Update the database
        cursor.execute("UPDATE users SET profile_pic = %s WHERE id_user = %s", (filename, session.get('id_user')))
        mysql.connection.commit()

        # Update the session variable
        session['profile_pic'] = filename

        flash('Profile picture updated successfully!', 'success')
        cursor.close()
        return redirect(url_for('profile'))

    # Retrieve current profile pic for rendering form
    cursor.execute("SELECT profile_pic FROM users WHERE id_user = %s", (session.get('id_user'),))
    user = cursor.fetchone()
    profile_pic = user[0] if user else None
    cursor.close()

    return render_template(
        "actions.html",
        profile_pic=profile_pic,
        profilForm=profilForm,
        signup_account_form = signup_account_form,
        payment_form = payment_form,
        checkBalance_form = checkBalance_form,
        time=time
    )

@app.route('/profile')
def profile():
    signup_account_form = Signup_account()
    payment_form = Payment()
    checkBalance_form = CheckBalance()
    profilForm = ProfilePicForm()
    login_form = Login()
    signup_form = Signup_app()
    id_user = session.get('id_user')
    
    if not id_user:
        flash('You must be logged in to access this page.', 'danger')
        return render_template("index.html", login_form=login_form, signup_form=signup_form, connexion=False)

    
    username = session['username']

    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT id_payment, payment_date, payment_time, historical.amount, account_number_sender, account_number_beneficiary, username, name_card, payment_reason, payment_status "
        "FROM historical, users, account WHERE %s=historical.id_user AND account.account_number=historical.account_number_sender AND username=%s", 
        (session['id_user'], username)
    )
    transactions = cursor.fetchall()

    cursor.execute("SELECT profile_pic FROM users WHERE id_user = %s", (session.get('id_user'),))
    user = cursor.fetchone()
    profile_pic = user[0] if user else 'images/welcome_back.png'
    cursor.close()
    
    # Update session with profile_pic
    session['profile_pic'] = profile_pic
    
    return render_template('actions.html', profilForm=profilForm, signup_account_form=signup_account_form, payment_form=payment_form, checkBalance_form=checkBalance_form, time=time, profile_pic=profile_pic, transactions=transactions, username=username)


@app.route('/delete_history', methods=['POST', 'GET'])
def delete_history():
    if 'id_user' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM historical WHERE id_user = %s", (session['id_user'],))
    mysql.connection.commit()
    cursor.close()
    return jsonify({"success": True}), 200




if __name__ == "__main__":
    app.run(debug=True)
