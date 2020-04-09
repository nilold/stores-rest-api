import os

from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager

from resources.item import Item, ItemList
from resources.store import Store, StoreList
from resources.user import UserRegister, User, UserLogin, TokenRefresh

from users_blacklist import BLACKLIST

app = Flask(__name__)

app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

app.secret_key = 'jose'
api = Api(app)

jwt = JWTManager(app)  # /auth


@jwt.user_claims_loader
def add_claims_to_jwt(identity):
    if identity == 1:
        return {'is_admin': True}  # just and example... this should come from db or something
    return {'is_admin': False}


@jwt.token_in_blacklist_loader
def is_in_blacklist(decrypted_token):
    return decrypted_token['identity'] in BLACKLIST


@jwt.expired_token_loader
def expired_token_callback(error):
    return jsonify({
        "description": "Your token has expired. Please refresh it ar /refresh using you refresh token.",
        "error": "token_expired"
    }), 401


@jwt.needs_fresh_token_loader
def needs_fresh_token_callback():
    return jsonify({
        "description": "This endpoint requires a fresh token. Please log in again.",
        "error": "token_no_fresh"
    }), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return "Invalid token!", 401


@jwt.unauthorized_loader
def unauthorized_callback(error):
    return "Get back, boy! You're not welcome here!", 401


@jwt.revoked_token_loader
def unauthorized_callback():
    return "Get back, boy! You're not welcome here ANYMORE!", 401


api.add_resource(Store, '/store/<string:name>')
api.add_resource(Item, '/item/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(StoreList, '/stores')

api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserRegister, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(TokenRefresh, '/refresh')

if __name__ == '__main__':
    from db import db

    db.init_app(app)

    if app.config['DEBUG']:
        @app.before_first_request
        def create_tables():
            db.create_all()

    app.run(port=5000)
