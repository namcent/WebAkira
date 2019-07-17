from wtforms import Form 
from wtforms import StringField, PasswordField
from wtforms import validators

class FormLogin(Form):
	
	user = StringField('Usuario', validators=[Required("El Usuario es requerido")])
	password = PasswordField('Contraseña', validators=[Required("El password es requerido")])
