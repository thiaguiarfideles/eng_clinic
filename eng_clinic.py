import smtplib
from email.mime.text import MIMEText
from flask import Flask, render_template, request,flash, url_for, redirect, current_app, Response
from datetime import date, datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, text
from sqlalchemy.orm import Session
from werkzeug.security import check_password_hash
from flask_login import LoginManager, UserMixin, current_user, login_required,login_user,logout_user
from functools import wraps
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField, PasswordField, DateField,SubmitField, validators, ValidationError,SelectField, FileField
from wtforms.validators import DataRequired, Length, Email
#from wtforms import StringField, SelectField, FileField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
from utils import generate_random_token
from flask_migrate import Migrate
#from wtforms.fields.html5 import DateField
import os
import bcrypt
import logging
import yaml
import csv
import io



def ler_query(caminho_do_arquivo, encoding=None):
    with open(caminho_do_arquivo, 'r', encoding=encoding) as myfile:
        query = myfile.read()
    return query
# Carregar as configurações do arquivo YAML
with open("config.yaml", "r") as config_file:
    config = yaml.safe_load(config_file)

app = Flask(__name__)
app.secret_key = 'uaie4q*(eo7ms*8vl_mde6x+a(&vx8nphm2o5n^=h0=p^3@u2'


# Configurações do servidor de e-mail
EMAIL_FROM = 'seumkt@gmail.com' #email de origem 
EMAIL_TO = 'thiaguiarfideles@live.com' #email de destino
SENHA = 'pmsertnxkggkqqvc'



PG_DBNAME = config["PG_DBNAME"]
PG_USER = config["PG_USER"]
PG_PASSWORD = config["PG_PASSWORD"]
PG_HOST = config["PG_HOST"]
PG_PORT = config["PG_PORT"]


# Atualizar a conexão com o banco de dados
os.environ["DATABASE_URI"] = f'postgresql://{PG_USER}:{PG_PASSWORD}@{PG_HOST}:{PG_PORT}/{PG_DBNAME}'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'uploads'  # Pasta onde os arquivos serão salvos
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}  # Extensões de arquivo permitidas

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class users(db.Model, UserMixin):
    
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    registration_number = db.Column(db.String(20), unique=True, nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    is_approved = db.Column(db.Boolean, default=False)
    email = db.Column(db.String, unique=True, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(100), unique=True, nullable=True)
    password_reset_expiration = db.Column(db.DateTime, nullable=True)
    current_password = db.Column(db.String(500), nullable=True)
    new_password = db.Column(db.String(500), nullable=True)

    def __repr__(self):
        return f"<users {self.username}>"
    
    def is_user_approved(self):
        """Check if the user is approved."""
        return self.is_approved

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.username

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.is_approved

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False
    
    def is_active(self):
        """Return True if the user is active."""
        return True  # You can modify this logic based on your requirement
#hashed_password = bcrypt.generate_password_hash(users.password).decode('utf-8')

class CadFornecedor(db.Model):
    __tablename__ = 'cadfornecedor'
    id_fornecedor = db.Column(db.Integer, primary_key=True, unique=True)
    CNPJ = db.Column(db.String(130), nullable=False)
    Razao_Social = db.Column(db.String(100), nullable=False)
    Nome_Fantasia = db.Column(db.String(100), nullable=False)
    Endereco = db.Column(db.String(100), nullable=False)
    Numero = db.Column(db.String(10), nullable=False)
    Complemento = db.Column(db.String(50))
    Bairro = db.Column(db.String(50), nullable=False)
    CEP = db.Column(db.String(9), nullable=False)
    Cidade = db.Column(db.String(50), nullable=False)
    UF = db.Column(db.String(2), nullable=False)
    Pais = db.Column(db.String(50), nullable=False)
    Telefone = db.Column(db.String(15), nullable=False)
    Ramal = db.Column(db.String(10))
    Celular = db.Column(db.String(15), nullable=False)
    Contato = db.Column(db.String(100), nullable=False)
    Email = db.Column(db.String, nullable=False)
    Site = db.Column(db.String)
    Fabricante = db.Column(db.Boolean, default=False)
    Fornecedor = db.Column(db.Boolean, default=False)
    Observacoes = db.Column(db.Text)

    def __init__(self, CNPJ, Razao_Social, Nome_Fantasia, Endereco, Numero, Bairro, CEP, Cidade, UF, Pais, Telefone, Celular, Contato, Email):
        self.CNPJ = CNPJ
        self.Razao_Social = Razao_Social
        self.Nome_Fantasia = Nome_Fantasia
        self.Endereco = Endereco
        self.Numero = Numero
        self.Bairro = Bairro
        self.CEP = CEP
        self.Cidade = Cidade
        self.UF = UF
        self.Pais = Pais
        self.Telefone = Telefone
        self.Celular = Celular
        self.Contato = Contato
        self.Email = Email

    def __str__(self):
        return self.Nome_Fantasia

class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo_material = db.Column(db.String(20), nullable=False)
    material = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(255))
    unidade_medida = db.Column(db.String(10), nullable=False)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    quantidade = db.Column(db.Integer)


    def __init__(self, tipo_material, material, descricao, unidade_medida, quantidade):
        self.tipo_material = tipo_material
        self.material = material
        self.descricao = descricao
        self.unidade_medida = unidade_medida
        self.quantidade = quantidade
        

class item_material(db.Model):
    id_itmaterial = db.Column(db.Integer, primary_key=True)
    material_id = db.Column(db.Integer, db.ForeignKey('material.id'), nullable=False)
    fabricante_id = db.Column(db.Integer, db.ForeignKey('cadfornecedor.id_fornecedor'), nullable=False)
    modelo = db.Column(db.String(100))
    complemento = db.Column(db.String(100))
    foto_material = db.Column(db.String(255))
    quantidade = db.Column(db.Integer)  # Adiciona a coluna "quantidade"
    tipo_material_id = db.Column(db.Integer, db.ForeignKey('material.id'), nullable=False)
    unidade_medida_id = db.Column(db.Integer, db.ForeignKey('material.id'), nullable=False)
    data_consumo = db.Column(db.DateTime)

    material = db.relationship('Material', foreign_keys=[material_id])
    fabricante = db.relationship('CadFornecedor', foreign_keys=[fabricante_id])
    tipo_material = db.relationship('Material', foreign_keys=[tipo_material_id])
    unidade_medida = db.relationship('Material', foreign_keys=[unidade_medida_id])
    
    

class CadastroItemMaterialForm(FlaskForm):
    material = SelectField('Material', coerce=int, validators=[DataRequired()])
    fabricante = SelectField('Fabricante', coerce=int, validators=[DataRequired()])
    modelo = StringField('Modelo')
    complemento = StringField('Complemento')
    foto_material = FileField('Foto do Material')
    quantidade = IntegerField('Quantidade', validators=[DataRequired()])  # Campo para "quantidade"
    tipo_material = SelectField('Tipo de Material', coerce=int, validators=[DataRequired()])
    unidade_medida = SelectField('Unidade medida', coerce=int, validators=[DataRequired()])
    data_consumo = DateField('Data de Consumo')
    

class Cliente(db.Model):
    __tablename__ = 'cliente'

    id_cliente = db.Column(db.Integer, primary_key=True, unique=True)
    cnpj = db.Column(db.String(18), nullable=True)
    nome_fantasia = db.Column(db.String(100), nullable=True)
    razao_social = db.Column(db.String(100), nullable=True)
    nome_pessoa_fisica = db.Column(db.String(100), nullable=True)
    endereco = db.Column(db.String(100), nullable=True)
    numero = db.Column(db.String(10), nullable=True)
    complemento = db.Column(db.String(50), nullable=True)
    bairro = db.Column(db.String(50), nullable=True)
    cep = db.Column(db.String(9), nullable=True)
    cidade = db.Column(db.String(50), nullable=True)
    uf = db.Column(db.String(2), nullable=True)
    pais = db.Column(db.String(50), nullable=True)
    telefone = db.Column(db.String(15), nullable=True)
    ramal = db.Column(db.String(10), nullable=True)
    email = db.Column(db.String, unique=True, nullable=True)
    site = db.Column(db.String, nullable=True)
    observacoes = db.Column(db.Text, nullable=True)
    diretor = db.Column(db.String(100), nullable=True)
    telefone_diretor = db.Column(db.String(15), nullable=True)


class TipoOS(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo_os = db.Column(db.String(255), nullable=False)
    observacoes = db.Column(db.Text, nullable=True)

    def __init__(self, tipo_os, observacoes):
        self.tipo_os = tipo_os
        self.observacoes = observacoes

class CentroCusto(db.Model):
    __tablename__ = 'centro_custo'
    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(30), nullable=False)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id_cliente'), nullable=False)
    
    cliente = db.relationship('Cliente', foreign_keys=[cliente_id])
    
class Setor(db.Model):
    __tablename__ = 'setor'
    id_setor = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(10))
    setor = db.Column(db.String(255))
    chefe = db.Column(db.String(255))
    observacao = db.Column(db.Text)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id_cliente'), nullable=False)
    cliente = db.relationship('Cliente', foreign_keys=[cliente_id])
    
    
class EntradaAcessorios(db.Model):
    __tablename__ = 'entrada_acessorios'
    id_acessorio = db.Column(db.Integer, primary_key=True)
    material_id = db.Column(db.Integer, db.ForeignKey('material.id'), nullable=False)
    material = db.relationship('Material', foreign_keys=[material_id])
    fabricante_id = db.Column(db.Integer, db.ForeignKey('cadfornecedor.id_fornecedor'), nullable=False)
    fabricante = db.relationship('CadFornecedor', foreign_keys=[fabricante_id])
    item_material = db.Column(db.String(255))
    rm = db.Column(db.String(255))
    situacao = db.Column(db.String(50))
    aquisicao = db.Column(db.String(50))
    setor_id = db.Column(db.Integer, db.ForeignKey('setor.id_setor'), nullable=False)
    setor = db.relationship('Setor', foreign_keys=[setor_id])
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id_cliente'), nullable=False)
    cliente = db.relationship('Cliente', foreign_keys=[cliente_id])
    localizacao = db.Column(db.String(255))    


class Agendamento(db.Model):
    __tablename__ = 'agendamento'

    id_agendamento = db.Column(db.Integer, primary_key=True)
    data_agendamento = db.Column(db.Date, nullable=False)
    data_lancamento = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    tipo_servico = db.Column(db.String(20), nullable=False)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id_cliente'), nullable=False)
    cliente = db.relationship('Cliente', foreign_keys=[cliente_id])
    observacoes = db.Column(db.String(255))

    

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    

class PasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Nova Senha', validators=[validators.DataRequired(),validators.EqualTo('confirm_password', message='Senhas devem ser iguais')])
    confirm_password = PasswordField('Confirme a Nova Senha', validators=[validators.DataRequired()])
    submit = SubmitField('Redefinir Senha')
    

class PasswordEditForm(FlaskForm):
    current_password = PasswordField('Senha Atual', validators=[validators.DataRequired()])
    new_password = PasswordField('Nova Senha', validators=[validators.DataRequired(), validators.EqualTo('confirm_password', message='Senhas devem ser iguais')])
    confirm_password = PasswordField('Confirme a Nova Senha', validators=[validators.DataRequired()])
    submit = SubmitField('Alterar Senha')  

@login_manager.user_loader
def user_loader(user_id):
    # Retrieve the user from the database using the username
    user = users.query.filter_by(username=user_id).first()
    return user


def send_approval_notification(email):
    sender_email = EMAIL_USERNAME
    sender_password = EMAIL_PASSWORD
    receiver_email = email
    subject = "Novos Registros Pendentes de aprovação"
    body = f"Prezado usuário,\n\nSeu cadastro está pendente de aprovação. Por favor, aguarde a revisão do administrador.\n\nCom os melhores cumprimentos,\ndo Administrador"

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    message.attach(MIMEText(body, "plain"))

    # Replace 'smtp-mail.outlook.com' with your Outlook SMTP server
    server = smtplib.SMTP("smtp-mail.outlook.com", 587)
    server.starttls()

    # Replace 'EMAIL_PASSWORD' with the actual email password or app password
    server.login(sender_email, sender_password)

    server.sendmail(sender_email, receiver_email, message.as_string())
    server.quit()


# Route for user registration
@app.route('/registro', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        registration_number = request.form['registration_number']
        date_of_birth = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d').date()
        email = request.form['email']
        admin = bool(request.form.get('admin'))
        
        admin = request.form.get('admin') == 'True'
        
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Set registration timestamp
        registered_on = datetime.utcnow()

        # Create a new User object and add it to the database with is_approved=False
        new_user = users(username=username, password=hashed_password, full_name=full_name,
                        registration_number=registration_number, date_of_birth=date_of_birth,
                        is_approved=True, email=email, admin=admin, registered_on=registered_on)
        db.session.add(new_user)
        db.session.commit()
        
        #send_approval_notification(EMAIL_USERNAME)
        
        # Redirect to a page informing the user that their registration is pending approval
        return redirect(url_for('registro_pendente'))

    return render_template('register.html')


# Route for displaying a page informing the user that their registration is pending approval
@app.route('/registro_pendente')
def registro_pendente():
    return render_template('registration_pending.html')

def requires_approval(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Você precisa ser aprovado para acessar esta página.", "warning")
            return redirect(url_for("login"))

        # Call the original route function with the provided arguments
        return func(*args, **kwargs)

    return decorated_function

# Example route that requires user approval
@app.route('/protecao_aprovacao')
@requires_approval
def protecao_aprovacao():
    # Your route logic here
    return render_template('modelo_aprovacao.html')

@app.route('/aprova_usuarios', methods=['GET', 'POST'])
def aprova_usuarios():
    # Get a list of all users who need approval (is_approved is False)
    pending_users = users.query.filter_by(is_approved=False).all()

    if not pending_users:
        # Handle the case where there are no pending users
        flash("Não existem usuario pendentes de aprovação.", "info")
        return redirect(url_for('index'))  # Redirect to the main page or any other relevant page

    if request.method == 'POST':
        # Handle the form submission to approve or reject users
        try:
            for user in pending_users:
                # Get the checkbox value for each user from the submitted form
                approval_status = request.form.get(str(user.id))

                if approval_status == 'approve':
                    # If the checkbox is checked (value is 'approve'), approve the user
                    user.is_approved = True

                    # Set the confirmation timestamp
                    user.confirmed_on = datetime.utcnow()
                else:
                    # If the checkbox is not checked (value is 'reject'), reject the user
                    # You can add additional handling here, such as sending a notification to the user
                    # that their registration has been rejected.
                    user.is_approved = False

            # Commit the changes to the database after processing all users
            db.session.commit()

            # Redirect to a success page or any other relevant page after processing approvals/rejections
            return redirect(url_for('approval_success'))

        except Exception as e:
            # Handle any potential errors during database update
            flash("Ocorreu um erro na aprovação do usuario.", "danger")
            # You may want to log the error for further investigation
            print("Error:", str(e))

            # Redirect back to the approval page to retry or handle the error gracefully
            return redirect(url_for('aprova_usuarios'))

    # Render the approval page with the list of users who need approval
    return render_template('approve_users.html', users=pending_users)



@app.route('/approval_success')
def approval_success():
    # Render a success page to show that the user has been approved
    flash("Usuario aprovado com sucesso!", "success")
    return render_template('approval_success.html')



#from . import LoginForm
logging.basicConfig(level=logging.DEBUG)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = users.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            if user.is_approved:
                login_user(user, remember=True)
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Seu registro está pendente de aprovação. Aguarde ou entre em contato com o administrador do sistema...', 'error')
        else:
            flash('Nome de usuário ou senha incorretos', 'error')

    return render_template('login.html', form=form)



@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()  # Use the logout_user() function to log the user out
    return render_template("logout.html")

def send_password_reset_email(email, token):
    sender_email = EMAIL_USERNAME
    sender_password = EMAIL_PASSWORD
    receiver_email = email

    subject = "Redefinição de Senha"
    reset_url = url_for('reset_password_token', token=token, _external=True)

    body = f"Prezado usuário,\n\nClique no link a seguir para redefinir sua senha:\n\n{reset_url}\n\nCom os melhores cumprimentos,\nO Administrador"

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    server = smtplib.SMTP("smtp-mail.outlook.com", 587)
    server.starttls()
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, receiver_email, message.as_string())
    server.quit()
    

@app.route('/edit_password', methods=['GET', 'POST'])
@login_required
def edit_password():
    form = PasswordEditForm()

    if form.validate_on_submit():
        user = current_user

        # Verifica se a senha atual corresponde
        if bcrypt.check_password_hash(user.password, form.current_password.data):
            # Gera o novo hash da nova senha
            hashed_new_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            user.password = hashed_new_password
            db.session.commit()

            flash('Sua senha foi alterada com sucesso.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Senha atual incorreta.', 'danger')

    return render_template('edit_password.html', form=form)


    

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = PasswordResetForm()

    if form.validate_on_submit():
        # Gere um token de redefinição de senha e armazene no banco de dados
        token = generate_random_token()  # Implemente a geração do token
        print("Generated Token:", token)

        # Atualize o usuário com o token e data de expiração no banco de dados
        user = users.query.filter_by(email=form.email.data).first()
        if user:
            print("User Found:", user.username)
            user.password_reset_token = token
            user.password_reset_expiration = datetime.utcnow() + timedelta(hours=1)  # Por exemplo, token expira em 1 hora
            db.session.commit()
            print("Token and Expiration Updated")

            # Envie o email de redefinição de senha
            #send_password_reset_email(user.email, token)

            flash('Um link de redefinição de senha foi enviado para o seu email.', 'info')
            return redirect(url_for('login'))  # Redirecionar para a página de login
        else:
            print("User Not Found")

    return render_template('reset_password.html', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    user = users.query.filter_by(password_reset_token=token).first()
    if user and user.password_reset_expiration > datetime.utcnow():
        form = PasswordResetForm()

        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password = hashed_password
            user.password_reset_token = None
            user.password_reset_expiration = None
            db.session.commit()

            flash('Sua senha foi redefinida com sucesso.', 'success')
            return redirect(url_for('login'))

        return render_template('reset_password_token.html', form=form, token=token)

    flash('O link de redefinição de senha é inválido ou expirou.', 'danger')
    return redirect(url_for('login'))   
    
@app.route('/')
@requires_approval
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('Arquivo enviado com sucesso', 'success')
    else:
        flash('Tipo de arquivo não permitido', 'danger')
    return redirect(url_for('index'))

# Rota para exibir o formulário de cadastro
@app.route('/cadastro_fornecedor', methods=['GET', 'POST'])
def cadastro_fornecedor():
    if request.method == 'POST':
        cnpj = request.form['cnpj']
        razao_social = request.form['razao_social']
        nome_fantasia = request.form['nome_fantasia']
        Endereco = request.form['Endereco']
        Numero = request.form['Numero']
        Bairro = request.form['Bairro']
        CEP = request.form['CEP']
        Cidade = request.form['Cidade']
        UF = request.form['UF']
        Pais = request.form['Pais']
        Telefone = request.form['Telefone']
        Celular = request.form['Celular']
        Contato = request.form['Contato']
        Email = request.form['Email']
        # Preencha com os demais campos

        fornecedor = CadFornecedor(
            CNPJ=cnpj,
            Razao_Social=razao_social,
            Nome_Fantasia=nome_fantasia,
            Endereco=Endereco,
            Numero=Numero,
            Bairro=Bairro,
            CEP=CEP,
            Cidade=Cidade,
            UF=UF,
            Pais=Pais,
            Telefone=Telefone,
            Celular=Celular,
            Contato=Contato,
            Email=Email,
            # Preencha com os demais campos
        )

        db.session.add(fornecedor)
        db.session.commit()

        flash('Fornecedor cadastrado com sucesso', 'success')
        return redirect(url_for('cadastro_fornecedor'))

    return render_template('cadastro_fornecedor.html')


# Rota para exibir a lista de fornecedores
@app.route('/fornecedores_list', methods=['GET'])
def fornecedores_list():
    search_query = request.args.get('search', default='', type=str)
    
    if search_query:
        # Realize a consulta filtrando os fornecedores com base no campo de pesquisa
        fornecedores = CadFornecedor.query.filter(
            (CadFornecedor.CNPJ.contains(search_query)) |
            (CadFornecedor.Razao_Social.contains(search_query)) |
            (CadFornecedor.Nome_Fantasia.contains(search_query))
            # Adicione mais campos para pesquisa conforme necessário
        ).all()
    else:
        # Sem consulta, exibe todos os fornecedores
        fornecedores = CadFornecedor.query.all()
    return render_template('fornecedores_lista.html', fornecedores=fornecedores)


@app.route('/editar_fornecedor/<int:id_fornecedor>', methods=['GET', 'POST'])
def editar_fornecedor(id_fornecedor):
    fornecedor = CadFornecedor.query.get(id_fornecedor)

    if request.method == 'POST':
        # Atualize os campos com os dados do formulário
        fornecedor.CNPJ = request.form['cnpj']
        fornecedor.Razao_Social = request.form['razao_social']
        fornecedor.Nome_Fantasia = request.form['nome_fantasia']
        fornecedor.Endereco = request.form['Endereco']
        fornecedor.Numero = request.form['Numero']
        fornecedor.Bairro = request.form['Bairro']
        fornecedor.CEP = request.form['CEP']
        fornecedor.Cidade = request.form['Cidade']
        fornecedor.UF = request.form['UF']
        fornecedor.Pais = request.form['Pais']
        fornecedor.Telefone = request.form['Telefone']
        fornecedor.Celular = request.form['Celular']
        fornecedor.Contato = request.form['Contato']
        fornecedor.Email = request.form['Email']

        db.session.commit()
        flash('Fornecedor atualizado com sucesso', 'success')
        return redirect(url_for('fornecedores_list'))

    return render_template('editar_fornecedor.html', fornecedor=fornecedor)

@app.route('/excluir_fornecedor/<int:id_fornecedor>', methods=['POST'])
def excluir_fornecedor(id_fornecedor):
    fornecedor = CadFornecedor.query.get(id_fornecedor)

    if fornecedor:
        db.session.delete(fornecedor)
        db.session.commit()
        flash('Fornecedor excluído com sucesso', 'success')

    return redirect(url_for('fornecedores_list'))


@app.route('/cadastro_cliente', methods=['GET', 'POST'])
def cadastro_cliente():
    if request.method == 'POST':
        cnpj = request.form['cnpj']
        nome_fantasia = request.form['nome_fantasia']
        razao_social = request.form['razao_social']
        nome_pessoa_fisica = request.form['nome_pessoa_fisica']
        endereco = request.form['endereco']
        numero = request.form['numero']
        complemento = request.form['complemento']
        bairro = request.form['bairro']
        cep = request.form['cep']
        cidade = request.form['cidade']
        uf = request.form['uf']
        pais = request.form['pais']
        telefone = request.form['telefone']
        ramal = request.form['ramal']
        email = request.form['email']
        site = request.form['site']
        observacoes = request.form['observacoes']
        diretor = request.form['diretor']
        telefone_diretor = request.form['telefone_diretor']

        novo_cliente = Cliente(
            cnpj=cnpj,
            nome_fantasia=nome_fantasia,
            razao_social=razao_social,
            nome_pessoa_fisica=nome_pessoa_fisica,
            endereco=endereco,
            numero=numero,
            complemento=complemento,
            bairro=bairro,
            cep=cep,
            cidade=cidade,
            uf=uf,
            pais=pais,
            telefone=telefone,
            ramal=ramal,
            email=email,
            site=site,
            observacoes=observacoes,
            diretor=diretor,
            telefone_diretor=telefone_diretor
        )

        db.session.add(novo_cliente)
        db.session.commit()

        flash('Cliente cadastrado com sucesso', 'success')
        return redirect(url_for('cadastro_cliente'))

    return render_template('cadastro_cliente.html')

@app.route('/listar_clientes', methods=['GET'])
def listar_clientes():
    clientes = Cliente.query.all()
    return render_template('listar_clientes.html', clientes=clientes)

@app.route('/pesquisar_clientes', methods=['GET'])
def pesquisar_clientes():
    search_query = request.args.get('search', default='', type=str)

    if search_query:
        # Use a pesquisa para filtrar os resultados da consulta
        clientes = Cliente.query.filter(
            (Cliente.nome_fantasia.like(f'%{search_query}%')) |
            (Cliente.razao_social.like(f'%{search_query}%')) |
            (Cliente.nome_pessoa_fisica.like(f'%{search_query}%'))
        ).all()
    else:
        # Se a consulta de pesquisa estiver vazia, obtenha todos os clientes
        clientes = Cliente.query.all()

    return render_template('listar_clientes.html', clientes=clientes, search_query=search_query)


@app.route('/update_cliente/<int:id_cliente>', methods=['GET', 'POST'])
def update_cliente(id_cliente):
    cliente = Cliente.query.get(id_cliente)
    if request.method == 'POST':
        cliente.cnpj = request.form['cnpj']
        cliente.nome_fantasia = request.form['nome_fantasia']
        cliente.razao_social = request.form['razao_social']
        cliente.nome_pessoa_fisica = request.form['nome_pessoa_fisica']
        cliente.endereco = request.form['endereco']
        cliente.numero = request.form['numero']
        cliente.complemento = request.form['complemento']
        cliente.bairro = request.form['bairro']
        cliente.cep = request.form['cep']
        cliente.cidade = request.form['cidade']
        cliente.uf = request.form['uf']
        cliente.pais = request.form['pais']
        cliente.telefone = request.form['telefone']
        cliente.ramal = request.form['ramal']
        cliente.site = request.form['site']
        cliente.observacoes = request.form['observacoes']
        cliente.diretor = request.form['diretor']
        cliente.telefone_diretor = request.form['telefone_diretor']

        db.session.commit()
        flash('Cliente atualizado com sucesso', 'success')
        return redirect(url_for('listar_clientes'))

    return render_template('update_cliente.html', cliente=cliente)


@app.route('/delete_cliente/<int:id_cliente>', methods=['POST'])
def delete_cliente(id_cliente):
    cliente = Cliente.query.get(id_cliente)
    db.session.delete(cliente)
    db.session.commit()
    flash('Cliente excluído com sucesso', 'success')
    return redirect(url_for('cadastro_cliente'))



@app.route('/cadastro_materiais', methods=['GET', 'POST'])
def cadastro_materiais():
    if request.method == 'POST':
        tipo_material = request.form['tipo_material']
        material = request.form['material']
        descricao = request.form['descricao']
        unidade_medida = request.form['unidade_medida']
        quantidade = request.form['quantidade']

        novo_material = Material(
            tipo_material=tipo_material,
            material=material,
            descricao=descricao,
            unidade_medida=unidade_medida,
            quantidade=quantidade
        )
        
        db.session.add(novo_material)
        db.session.commit()

    materiais = Material.query.all()

    return render_template('cadastro_materiais.html', materiais=materiais)

@app.route('/listar_materiais', methods=['GET'])
def listar_materiais():
    search_query = request.args.get('search', default='', type=str)
    # Consulta base para listar todos os materiais
    query = Material.query

    if search_query:
        # Aplicar o filtro apenas se uma consulta de pesquisa for fornecida
        query = query.filter(
            (Material.material.contains(search_query)) |
            (Material.descricao.contains(search_query))
        )

    materiais = query.all()
    return render_template('listar_materiais.html', materiais=materiais)


@app.route('/editar_material/<int:id_material>', methods=['GET', 'POST'])
def editar_material(id_material):
    material = Material.query.get(id_material)

    if request.method == 'POST':
        # Atualize os campos com os dados do formulário
        material.tipo_material = request.form['tipo_material']
        material.material = request.form['material']
        material.descricao = request.form['descricao']
        material.unidade_medida = request.form['unidade_medida']
        material.quantidade = request.form['quantidade']

        db.session.commit()
        flash('Material atualizado com sucesso', 'success')
        return redirect(url_for('listar_materiais'))

    return render_template('editar_material.html', material=material)

@app.route('/excluir_material/<int:id_material>', methods=['POST'])
def excluir_material(id_material):
    material = Material.query.get(id_material)

    if material:
        db.session.delete(material)
        db.session.commit()
        flash('Material excluído com sucesso', 'success')

    return redirect(url_for('listar_materiais'))



@app.route('/item_material/cadastrar', methods=['GET', 'POST'])
def cadastrar_item_material():
    form = CadastroItemMaterialForm()
    form.fabricante.choices = [(f.id_fornecedor, f.Razao_Social) for f in CadFornecedor.query.all()]
    form.material.choices = [(m.id, m.material) for m in Material.query.all()]
    form.tipo_material.choices = [(m.id, m.tipo_material) for m in Material.query.all()]
    form.unidade_medida.choices = [(m.id, m.unidade_medida) for m in Material.query.all()]

    if form.validate_on_submit():
        material_id = int(form.material.data)
        fabricante_id = int(form.fabricante.data)
        modelo = form.modelo.data
        complemento = form.complemento.data
        quantidade = int(form.quantidade.data)
        tipo_material_id = int(form.tipo_material.data)
        unidade_medida = int(form.unidade_medida.data)
        data_consumo = form.data_consumo.data

        # Agora que você tem o ID do material, pode salvar a foto_material
        if 'foto_material' in request.files:
            foto_material = request.files['foto_material']
            if foto_material:
                filename = secure_filename(foto_material.filename)
                foto_material.save('media/itens_mat/' + filename)

        novo_itemmaterial = item_material(
            material_id=material_id,
            fabricante_id=fabricante_id,
            modelo=modelo,
            complemento=complemento,
            quantidade=quantidade,
            tipo_material_id=tipo_material_id,
            foto_material=filename,  # Salve o nome do arquivo, não o campo do formulário
            unidade_medida_id=unidade_medida,
            data_consumo=data_consumo
        )

        db.session.add(novo_itemmaterial)
        db.session.commit()
        itensmateriais = item_material.query.all()
        return render_template('cadastro_materiais.html', itensmateriais=itensmateriais)

    return render_template('itens_material.html', form=form)



@app.route('/cadastrar_tipo_os', methods=['GET', 'POST'])
def cadastrar_tipo_os():
    if request.method == 'POST':
        tipo_os = request.form['tipo_os']
        observacoes = request.form['observacoes']
        novo_tipo_os = TipoOS(
            tipo_os=tipo_os,
            observacoes=observacoes
            )
        db.session.add(novo_tipo_os)
        db.session.commit()
        return redirect(url_for('listar_tipos_os'))
    return render_template('cadastro_tipo_os.html')

@app.route('/listar_tipos_os')
def listar_tipos_os():
    tipos_os = TipoOS.query.all()
    return render_template('lista_tipos_os.html', tipos_os=tipos_os)



# Rota para listar todos os centros de custo
@app.route('/centros_custo', methods=['GET'])
def listar_centros_custo():
    centros_custo = CentroCusto.query.all()
    return render_template('lista_centros_custo.html', centros_custo=centros_custo)

# Rota para adicionar um novo centro de custo
@app.route('/centros_custo/novo', methods=['GET', 'POST'])
def adicionar_centro_custo():
    # Busque a lista de clientes para o formulário
    clientes = Cliente.query.all()
    
    if request.method == 'POST':
        codigo = request.form['codigo']
        cliente_id = request.form['cliente_id']

        centro_custo = CentroCusto(codigo=codigo, cliente_id=cliente_id)
        db.session.add(centro_custo)
        db.session.commit()
        flash('Centro de custo adicionado com sucesso!', 'success')
        return redirect(url_for('listar_centros_custo'))

    return render_template('cadastro_centro_custo.html', centro_custo=None, clientes=clientes)

# Rota para editar um centro de custo
@app.route('/centros_custo/editar/<int:id>', methods=['GET', 'POST'])
def editar_centro_custo(id):
    centro_custo = CentroCusto.query.get(id)
    
    if request.method == 'POST':
        codigo = request.form['codigo']
        cliente_id = request.form['cliente_id']
        
        centro_custo.codigo = codigo
        centro_custo.cliente_id = cliente_id

        db.session.commit()
        flash('Centro de custo atualizado com sucesso!', 'success')
        return redirect(url_for('listar_centros_custo'))
    
    # Busque a lista de clientes para o formulário
    clientes = Cliente.query.all()
    return render_template('editar_centro_custo.html', centro_custo=centro_custo, clientes=clientes)

# Rota para excluir um centro de custo
@app.route('/centros_custo/excluir/<int:id>', methods=['GET', 'POST'])
def excluir_centro_custo(id):
    centro_custo = CentroCusto.query.get(id)
    db.session.delete(centro_custo)
    db.session.commit()
    flash('Centro de custo excluído com sucesso!', 'success')
    return redirect(url_for('listar_centros_custo'))



@app.route('/listar_setores')
def listar_setores():
    setores = Setor.query.all()
    return render_template('lista_setores.html', setores=setores)

@app.route('/setores/novo', methods=['GET', 'POST'])
def adicionar_setor():
    if request.method == 'POST':
        codigo = request.form['codigo']
        setor = request.form['setor']
        cliente_id = request.form['cliente_id']
        chefe = request.form['chefe']
        observacao = request.form['observacao']

        novo_setor = Setor(codigo=codigo, setor=setor, cliente_id=cliente_id, chefe=chefe, observacao=observacao)
        db.session.add(novo_setor)
        db.session.commit()
        flash('Setor adicionado com sucesso!', 'success')
        return redirect(url_for('listar_setores'))

    clientes = Cliente.query.all()
    return render_template('cadastro_setor.html', clientes=clientes)

@app.route('/setores/editar/<int:id>', methods=['GET', 'POST'])
def editar_setor(id):
    setor = Setor.query.get(id)

    if request.method == 'POST':
        setor.codigo = request.form['codigo']
        setor.setor = request.form['setor']
        setor.cliente_id = request.form['cliente_id']
        setor.chefe = request.form['chefe']
        setor.observacao = request.form['observacao']

        db.session.commit()
        flash('Setor atualizado com sucesso!', 'success')
        return redirect(url_for('listar_setores'))

    clientes = Cliente.query.all()
    return render_template('editar_setor.html', setor=setor, clientes=clientes)

@app.route('/setores/excluir/<int:id>')
def excluir_setor(id):
    setor = Setor.query.get(id)
    db.session.delete(setor)
    db.session.commit()
    flash('Setor excluído com sucesso!', 'success')
    return redirect(url_for('listar_setores'))


@app.route('/acessorios/novo', methods=['GET', 'POST'])
def adicionar_acessorio():
    if request.method == 'POST':
        material_id = request.form['material_id']
        fabricante_id = request.form['fabricante_id']
        item_material = request.form['item_material']
        rm = request.form['rm']
        situacao = request.form['situacao']
        aquisicao = request.form['aquisicao']
        setor_id = request.form['setor_id']
        cliente_id = request.form['cliente_id']
        localizacao = request.form['localizacao']

        acessorio = EntradaAcessorios(
            material_id=material_id,
            fabricante_id=fabricante_id,
            item_material=item_material,
            rm=rm,
            situacao=situacao,
            aquisicao=aquisicao,
            setor_id=setor_id,
            cliente_id=cliente_id,
            localizacao=localizacao
        )

        db.session.add(acessorio)
        db.session.commit()
        flash('Acessório adicionado com sucesso!', 'success')
        return redirect(url_for('listar_acessorios'))

    # Recupere os materiais, fabricantes, setores e clientes para preencher o formulário
    materiais = Material.query.all()
    fabricantes = CadFornecedor.query.all()
    setores = Setor.query.all()
    clientes = Cliente.query.all()

    return render_template(
        'cadastro_acessorio.html',
        materiais=materiais,
        fabricantes=fabricantes,
        setores=setores,
        clientes=clientes
    )
    
@app.route('/listar_acessorios')
def listar_acessorios():
    acessorios = EntradaAcessorios.query.all()
    return render_template('lista_acessorios.html', acessorios=acessorios)

@app.route('/acessorios/editar/<int:id>', methods=['GET', 'POST'])
def editar_acessorio(id):
    acessorio = EntradaAcessorios.query.get(id)

    if request.method == 'POST':
        # Obtenha os dados do formulário
        material_id = request.form['material_id']
        fabricante_id = request.form['fabricante_id']
        item_material = request.form['item_material']
        rm = request.form['rm']
        situacao = request.form['situacao']
        aquisicao = request.form['aquisicao']
        setor_id = request.form['setor_id']
        cliente_id = request.form['cliente_id']
        localizacao = request.form['localizacao']

        # Verifique se os campos de ID não estão vazios ('')
        if material_id and fabricante_id and setor_id and cliente_id:
            # Converta os valores para inteiros
            material_id = int(material_id)
            fabricante_id = int(fabricante_id)
            setor_id = int(setor_id)
            cliente_id = int(cliente_id)

            # Atualize os campos do acessório
            acessorio.material_id = material_id
            acessorio.fabricante_id = fabricante_id
            acessorio.item_material = item_material
            acessorio.rm = rm
            acessorio.situacao = situacao
            acessorio.aquisicao = aquisicao
            acessorio.setor_id = setor_id
            acessorio.cliente_id = cliente_id
            acessorio.localizacao = localizacao

            db.session.commit()
            flash('Acessório atualizado com sucesso!', 'success')
            return redirect(url_for('listar_acessorios'))
        else:
            flash('Certifique-se de preencher todos os campos obrigatórios.', 'danger')

    # Recupere os materiais, fabricantes, setores e clientes para preencher o formulário
    materiais = Material.query.all()
    fabricantes = CadFornecedor.query.all()
    setores = Setor.query.all()
    clientes = Cliente.query.all()

    return render_template(
        'editar_acessorio.html',
        acessorio=acessorio,
        materiais=materiais,
        fabricantes=fabricantes,
        setores=setores,
        clientes=clientes
    )
    

@app.route('/acessorios/excluir/<int:id>')
def excluir_acessorio(id):
    acessorio = db.session.query(EntradaAcessorios).get(id)
    db.session.delete(acessorio)
    db.session.commit()
    flash('Acessório excluído com sucesso!', 'success')
    return redirect(url_for('listar_acessorios')) 

@app.route('/listar_agendamentos')
def listar_agendamentos():
    agendamentos = Agendamento.query.all()
    return render_template('lista_agendamentos.html', agendamentos=agendamentos)


@app.route('/agendamentos/novo', methods=['GET', 'POST'])
def adicionar_agendamento():
    if request.method == 'POST':
        data_agendamento = request.form['data_agendamento']
        tipo_servico = request.form['tipo_servico']
        cliente_id = request.form['cliente_id']
        observacoes = request.form['observacoes']

        agendamento = Agendamento(data_agendamento=data_agendamento, tipo_servico=tipo_servico, cliente_id=cliente_id, observacoes=observacoes)
        db.session.add(agendamento)
        db.session.commit()
        flash('Agendamento adicionado com sucesso!', 'success')

        # Envia um e-mail informando o problema
        assunto = 'Novo Agendamento Criado'
        corpo = f'Um novo agendamento foi criado.\nData do Agendamento: {data_agendamento}\nObservações: {agendamento.observacoes}\nTipo Serviço:{agendamento.tipo_servico}\nNome Cliente:{ agendamento.cliente.nome_fantasia }'
        msg = MIMEText(corpo)
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO
        msg['Subject'] = assunto
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_FROM, SENHA)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        server.quit()

        return redirect(url_for('listar_agendamentos'))

    # Busque a lista de clientes para o formulário
    clientes = Cliente.query.all()
    return render_template('cadastro_agendamento.html', clientes=clientes)



@app.route('/agendamentos/editar/<int:id>', methods=['GET', 'POST'])
def editar_agendamento(id):
    agendamento = Agendamento.query.get(id)

    if request.method == 'POST':
        agendamento.data_agendamento = request.form['data_agendamento']
        agendamento.tipo_servico = request.form['tipo_servico']
        agendamento.cliente_id = request.form['cliente_id']
        agendamento.observacoes = request.form['observacoes']

        db.session.commit()
        flash('Agendamento atualizado com sucesso!', 'success')
        return redirect(url_for('listar_agendamentos'))

    # Busque a lista de clientes para o formulário
    clientes = Cliente.query.all()
    return render_template('editar_agendamento.html', agendamento=agendamento, clientes=clientes)


@app.route('/agendamentos/excluir/<int:id>')
def excluir_agendamento(id):
    agendamento = Agendamento.query.get(id)
    if agendamento:
        db.session.delete(agendamento)
        db.session.commit()
        flash('Agendamento excluído com sucesso!', 'success')
    return redirect(url_for('listar_agendamentos'))

   


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 88))
    app.run(host='0.0.0.0', port=port)
