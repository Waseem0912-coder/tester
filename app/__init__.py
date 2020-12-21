  
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from config import Config
from flask_moment import Moment
from flask_mail import Mail

    #149      
 
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db) 
login = LoginManager(app)
login.login_view = 'login'
moment = Moment(app) 
mail = Mail(app)


from app import routes, models                 