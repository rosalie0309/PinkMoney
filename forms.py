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

                    
 
