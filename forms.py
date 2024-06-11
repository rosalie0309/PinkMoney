from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, DateField, IntegerField, PasswordField, EmailField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, NumberRange, AnyOf
from flask_wtf.file import FileField, FileRequired

class Signup_app(FlaskForm):
    lastname = StringField('Lastname', validators=[DataRequired()])
    firstname = StringField('Firstname', validators=[DataRequired()])
    birthday = DateField('Birthday', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long.'),
        Regexp('^(?=.*[A-Z])', message='Password must contain at least one uppercase letter.'),
        Regexp('^(?=.*[a-z])', message='Password must contain at least one lowercase letter.'),
        Regexp('^(?=.*\\d)', message='Password must contain at least one digit.'),
        Regexp('^(?=.*[@$!%*?&])', message='Password must contain at least one special character.')
    ])
    submit = SubmitField('Sign Up')  

class Signup_account(FlaskForm):
    name_card = StringField('Name_Card', validators=[DataRequired()])
    account_number = StringField('Account_Number', validators=[
        DataRequired(),
        AnyOf(['4', '16'], message='Account number must be either 4 or 16 characters long.')
    ])
    cvv = StringField('CVV', validators=[
        DataRequired(),
        Length(min=3, max=3, message='CVV must be exactly 3 digits long.')
    ])
    amount = IntegerField('Amount', validators=[
        DataRequired(),
        NumberRange(min=50000, message='Amount must be at least 50000.')
    ])
    pin_code = PasswordField('Code Pin', validators=[
        DataRequired(),
        Length(min=4, max=4, message='PIN code must be exactly 4 characters long.')
    ])
    fingerPrint = FileField('Finger Print', validators=[FileRequired()])
    submit = SubmitField('Sign Up')

class Payment(FlaskForm):
    account_number_sender = StringField("Sender's account number", validators=[DataRequired()])
    account_number_beneficiary = StringField("Beneficiary's account number", validators=[DataRequired()])
    cvv = StringField('CVV(Card Verification Value)', validators=[
        DataRequired(),
        Length(min=3, max=3, message='CVV must be exactly 3 digits long.')
    ])
    amount_be_paid = IntegerField('Amount to be paid', validators=[DataRequired()])
    pin_code = PasswordField('Code Pin', validators=[
        DataRequired(),
        Length(min=4, max=4, message='PIN code must be exactly 4 characters long.')
    ])
    reason_payment = StringField("Reason of payment", validators=[DataRequired()])



class CheckBalance(FlaskForm):
    account_number = StringField("Account Number", validators=[DataRequired()])
    pin_code = PasswordField('Code Pin', validators=[
        DataRequired(),
        Length(min=4, max=4, message='PIN code must be exactly 4 characters long.')
    ])

class Login(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])



class ProfilePicForm(FlaskForm):
    profile_pic = FileField('Profile Picture', validators=[FileRequired()])

                    
 
"""""
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
        account_number_sender = payment_form.account_number_sender.data
        account_number_beneficiary = payment_form.account_number_beneficiary.data
        amount_be_paid = float(payment_form.amount_be_paid.data)
        cvv = str(payment_form.cvv.data).strip()
        pin_code = payment_form.pin_code.data
        reason_payment = payment_form.reason_payment.data

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
    elif id_user is not None and request.method == "GET":
        return render_template("actions.html",profile_pic=session['profile_pic'], time=time, profilForm=profilForm, transactions=transactions, checkBalance_form=checkBalance_form, username=session.get('username'), signup_account_form=signup_account_form, payment_form=payment_form)
    else:
        flash('You must be logged in to access this page.', 'danger')
        return render_template("index.html", login_form=login_form, signup_form=signup_form, connexion=False)

        


"""