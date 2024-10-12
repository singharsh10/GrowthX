from flask import Flask
from flask_pymongo import PyMongo
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv('MONGO_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
mongo = PyMongo(app)

from routes import *

if __name__ == '__main__':
    app.run(debug=True)