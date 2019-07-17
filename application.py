from flask import Flask, render_template, request, redirect, url_for, flash
from flask import session as login_session
#tablas de la database
from database import Blog, User, Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import random
import string
import hashlib
from werkzeug.utils import secure_filename
import os

from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

import json
import datetime

import httplib2
import requests



app = Flask(__name__)

#carpeta donde se guardan las imagenes	de los posts
UPLOAD_FOLDER = 'static/imagenes/img-posts'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])


def allowed_file(filename):
	return '.' in filename and \
		filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#conexion a la database y creacion de database_session
engine = create_engine('postgresql://admin:12345678@localhost/ejemplo')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


#funciones de las rutas
#inicio
@app.route('/')
def index():
	posts = session.query(Blog).all() #trae todas los registros de la tabla Blog de la db
	if 'username' in login_session:
		return render_template('index.html',username = login_session['username'], posts=posts)
	else:
		return render_template('index.html',posts=posts)


#logueo
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'GET':
		return render_template("login.html")
	else:
		if request.method == 'POST':
			username = request.form['username'].lower()
			password = request.form['password']
			#tomo los datos del form que puso el usuario en el template
			registro = session.query(User).all()
			#toma todos los registros de la tabla user de la database
			for x in registro:
				if x.username == username: #compara el x.usuario(de la database) con el de la variable de arriba
					if x and valid_pw(username, password, x.pw_hash): #llama a la funcion que valida el pssword
						login_session['username'] = username #inicia la sesion
						return redirect(url_for('index'))#redirecciona a la funcion index
			flash ('no se encontraron usuarios registrados')
			return redirect(url_for('login'))


#deslogueo - delete session - elimina la sesion del usuario
@app.route('/logout')
def logout():
		
		del login_session['username']
		return redirect(url_for('index'))

#creacion de usuario 
@app.route('/registrar', methods=['GET', 'POST'])
def registrar():

	if request.method == 'GET':
		return render_template('add-user.html')
	else:                                
		if request.method == 'POST':
			username = request.form['username']
			password = request.form['password']
			email = request.form['email']
			registro = session.query(User).all()
			
			#valido que los campos no esten vacios			
			if username == '':
					flash("Ingrese un usuario")
					return redirect(url_for('registrar'))
			if password == '':
					flash("Ingrese un password")
					return redirect(url_for('registrar'))
			if email == '':
					flash("Ingrese un email")
					return redirect(url_for('registrar'))
					
			#valido que los usuarios y el email no esten registrados				
			for x in registro:
				if x.username == username:
					flash ('Error. Usuario ya registrado')
					return redirect(url_for('registrar'))
				else:
					if x.email == email:
						flash ('Error. Email ya registrado')
						return redirect(url_for('registrar'))
					else:			
						pw_hash = make_pw_hash(username, password)
						nuevoUsuario = User(
								username = username,
								email = email,
								pw_hash=pw_hash) 
						session.add(nuevoUsuario)
						session.commit()             
						login_session['username'] = request.form['username'] #crea la sesion del usuario
						flash('Usuario creado correctamente', 'success')
						return redirect(url_for('index'))
#creacion de post
@app.route('/agregarPost', methods=['GET', 'POST'])
def agregarPost():
	if 'username' in login_session:
		if request.method == 'GET':
			return render_template('add-post.html')
		else:
			if request.method == 'POST':
				registro = session.query(User).filter_by(username = login_session['username']).first()
				post=Blog(
						titulo = request.form['titulo'],
						contenido = request.form['contenido'],
						fecha_creacion = datetime.datetime.now(),
						id_user = registro.id)
				
				if 'foto' in request.files:
					file = request.files['foto']
					if file and allowed_file(file.filename):
						filename = secure_filename(file.filename)
						file.save(os.path.join(UPLOAD_FOLDER, filename))
						post.foto = filename
				session.add(post)
				session.commit()
				flash('Post creado correctamente', 'success')
				return redirect(url_for('index'))
	else:
		return redirect(url_for('index'))


#edicion de post
@app.route('/blog/editar/<int:id>',methods=['POST','GET'])
def editarPost(id):
	if 'username' in login_session:
		post = session.query(Blog).filter_by(id = id).one()

		if request.method == 'GET':
			return render_template('edit-post.html',post=post,username = login_session['username'])
		else:
			if 'foto' in request.files:
				file = request.files['foto']
				if file and allowed_file(file.filename):
					filename = secure_filename(file.filename)
					file.save(os.path.join(UPLOAD_FOLDER, filename))
					post.foto = filename
			post.titulo = request.form['titulo']
			post.contenido = request.form['contenido']

			session.add(post)
			session.commit()
			flash('Su post ha sido modificado', 'success')
			return redirect(url_for('index'))
	else:
		return redirect(url_for('index'))


#eliminacion de post
@app.route('/blog/eliminar/<int:id>',methods=['POST','GET'])
def eliminarPost(id):
	if 'username' in login_session:
		id = id
		post = session.query(Blog).filter_by(id = id).one()
		session.delete(post)
		session.commit()
		return redirect(url_for('index'))
	else:
		return redirect(url_for('index'))

#funcion mostrar ppal
@app.route('/public/<int:id>', methods=['GET'])
def showMain(id):

	posts = session.query(Blog).filter_by(id_user=id).all() 
	
	if 'username' in login_session:
		username = login_session['username']
		return render_template('public.html', posts = posts, username=username)	
	else:
		return render_template('public.html', posts = posts)

@app.route('/editar', methods=['GET'])
def editar():

	if 'username' in login_session:
		if login_session['username'] == 'admin': #verifica si el usuario en la sesion es admin
			posts = session.query(Blog).all() #si es admin trae todos los posts
			return render_template('public.html', posts = posts, username=login_session['username'])
		else:
			registro = session.query(User).filter_by(username = login_session['username']).one()
			posts = session.query(Blog).filter_by(id_user=registro.id).all()
			return render_template('public.html', posts = posts, username=login_session['username'])	
	else:
		redirect(url_for('index'))

#funciones para hashear la contraseña
def login_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if 'username' not in login_session:
			return redirect(url_for('login')) #si no esta logueado redirecciona a login
		return f(*args, **kwargs)
	return decorated_function

def make_salt():
	return ''.join(random.choice(
				string.ascii_uppercase + string.digits) for x in range(32))
		
def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256((name + pw + salt).encode('utf-8')).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h): #valida el password
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

#funciones para manejo de errores
@app.errorhandler(404)
def no_encontrado(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def error_interno(e):
    return render_template('500.html'), 500
    

if __name__ == ('__main__'):
	app.secret_key = "secret key"
	app.run('0.0.0.0', 8080, debug = True)	

