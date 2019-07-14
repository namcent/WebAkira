from wtforms import Form 
from wtforms import StringField, PasswordField

class FormLogin(Form):
	
	user = StringField('Usuario')
	password = PasswordField('Contraseña')
