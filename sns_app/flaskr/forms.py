from flask_wtf import FlaskForm
from wtforms.fields import (
    StringField, FileField, PasswordField,
    SubmitField, HiddenField, TextAreaField
)
from wtforms.validators import DataRequired, Email, EqualTo
from wtforms import ValidationError
from flask_login import current_user
from flask import flash

from flaskr.models import User, UserConnect


class LoginForm(FlaskForm):
    email = StringField(
        'mail: ', validators=[DataRequired(), Email()]
    )
    password = PasswordField(
        'Password: ',
        validators=[DataRequired(),
        EqualTo('confirm_password', message='Your password is not correct.')]
    )
    confirm_password = PasswordField(
        'Password Again?: ', validators=[DataRequired()]
    )
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    email = StringField(
        'Mail: ', validators=[DataRequired(), Email('Your email address is not correct.')]
    )
    username = StringField('Name: ', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.select_user_by_email(field.data):
            raise ValidationError('Your email address is already registered.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        'Password',
        validators=[DataRequired(), EqualTo('confirm_password', message='Your password is not correct.')]
    )
    confirm_password = PasswordField(
        'Password check', validators=[DataRequired()]
    )
    submit = SubmitField('Update your password')
    def validate_password(self, field):
        if len(field.data) < 8:
            raise ValidationError('Password should be more than 8 characters')


class ForgotPasswordForm(FlaskForm):
    email = StringField('Mail: ', validators=[DataRequired(), Email()])
    submit = SubmitField('New Password Register')

    def validate_email(self, field):
        if not User.select_user_by_email(field.data):
            raise ValidationError('This mail address does not exsist.')



class UserForm(FlaskForm):
    email = StringField(
        'Mail: ', validators=[DataRequired(), Email('Your address is not correct.')]
    )
    username = StringField('Name: ', validators=[DataRequired()])
    picture_path = FileField('File upload')
    submit = SubmitField('Update your info')

    def validate(self):
        if not super(FlaskForm, self).validate():
            return False
        user = User.select_user_by_email(self.email.data)
        if user:
            if user.id != int(current_user.get_id()):
                flash('This address is already registered.')
                return False
            return True

class ChangePasswordForm(FlaskForm):
    password = PasswordField(
        'Password',
        validators=[DataRequired(), EqualTo('confirm_password', message='Your password is not correct.')]
    )
    confirm_password = PasswordField(
        'Password check', validators=[DataRequired()]
    )
    submit = SubmitField('Password Update')
    def validate_password(self, field):
        if len(field.data) < 8:
            raise ValidationError('Password should be more than 8 characters')

class UserSearchForm(FlaskForm):
    username = StringField(
        'Name: ', validators=[DataRequired()]
    )
    submit = SubmitField('User Search')

class ConnectForm(FlaskForm):
    connect_condition = HiddenField()
    to_user_id = HiddenField()
    submit = SubmitField()

class MessageForm(FlaskForm):
    to_user_id = HiddenField()
    message = TextAreaField()
    submit = SubmitField('Send Message')

    def validate(self):
        if not super(FlaskForm, self).validate():
            return False
        is_friend = UserConnect.is_friend(self.to_user_id.data)
        if not is_friend:
            return False
        return True