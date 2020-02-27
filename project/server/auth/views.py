# project/server/auth/views.py

import requests
import random
import json

from flask import Blueprint, request, make_response, jsonify, redirect
from flask.views import MethodView

from project.server import bcrypt, db
from project.server.models import User, BlacklistToken

auth_blueprint = Blueprint('auth', __name__)

global_pin_store = {}

DETECTION_URL = 'http://localhost:5001/detection'
DEVICE_URL = 'http://localhost:5001/device'
SMS_URL = 'http://localhost:5002/sms'
CONTACTTRACE_URL = 'http://localhost:5001/contacttrace'


def check_valid_token():
    auth_header = request.headers.get('Authorization')
    if auth_header:
        try:
            auth_token = auth_header.split(" ")[1]
        except IndexError:
            print('check valid token: invalid auth_token')
            return False, None
    else:
        auth_token = ''
    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            user = User.query.filter_by(id=resp).first()
            if user is None:
                print('check valid token: user not found')
                return False, None
            return True, user
        print('check valid token: invalid token')
        return False, None
    else:
        return False, None


class RegisterAPI(MethodView):
    def post(self):
        # get the post data
        # post_data = request.get_json()
        post_data = json.loads(request.data)
        # check if user already exists

        phone_number = post_data.get('mobileNumber', None)
        if phone_number is None:
            responseObject = {
                'message': 'missing mobileNumber'
            }
            return make_response(jsonify(responseObject)), 428
        if phone_number not in global_pin_store:
            responseObject = {
                'message': 'have not requested for sms token'
            }
            return make_response(jsonify(responseObject)), 428
        else:
            pin = global_pin_store.pop(phone_number)

        sms_token = post_data.get('smsToken', None)
        if sms_token is None:
            return make_response(jsonify(
                {'message': 'missing smsToken'}
            )), 428

        # TEMP!!! skip 2fa check
        # if sms_token != pin:
        #     responseObject = {
        #         'message': '2fa failed'
        #     }
        #     return make_response(jsonify(responseObject)), 406

        # user = User.query.filter_by(email=post_data.get('email')).first()
        user = User.query.filter_by( \
            phone_number=post_data.get('mobileNumber')).first()
        if not user:
            try:
                # ============ create user
                user = User(
                    email=post_data.get('email', 'email'),
                    phone_number=post_data.get('mobileNumber'),
                    device_id=post_data['device']['id'],
                    password=post_data.get('password', 'password')
                )
                db.session.add(user)
                db.session.commit()

                # ======== create device
                requests.put(DEVICE_URL, json=post_data)

                # ======== return token
                auth_token = user.encode_auth_token(user.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'authToken': auth_token.decode()
                }
                print('res1: %s' % responseObject)
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            # ============ update user
            user.email = post_data.get('email', 'email')
            user.device_id = post_data['device']['id']
            user.password = post_data.get('password', 'password')
            db.session.commit()
            msg = 'User already exists, info updated. '

            # ======== update device
            requests.put(DEVICE_URL, json=post_data)
            msg += 'Device info updated. '

            auth_token = user.encode_auth_token(user.id)
            responseObject = {
                'message': msg,
                'authToken': auth_token.decode()
            }
            print('res2: %s' % responseObject)
            return make_response(jsonify(responseObject)), 202


class LoginAPI(MethodView):
    """
    User Login Resource
    """

    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            # fetch the user data
            # user = User.query.filter_by( email=post_data.get('email') ).first()
            user = User.query.filter_by(phone_number=post_data.get('mobileNumber')).first()
            if user and bcrypt.check_password_hash(
                    user.password, post_data.get('password')
            ):
                auth_token = user.encode_auth_token(user.id)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode()
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404
        except Exception as e:
            print(e)
            responseObject = {
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500


class UserAPI(MethodView):
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'phone_number': user.phone_number,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


class LogoutAPI(MethodView):
    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 401
            else:
                responseObject = {
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


# define the API resources
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)


class DeviceAPI(MethodView):
    def get(self):
        is_valid_token, user = check_valid_token()
        if not is_valid_token:
            return make_response(jsonify({'message': 'token issue'})), 401

        res = requests.get(DEVICE_URL)
        return make_response(jsonify(res.json())), 201

device_view = DeviceAPI.as_view('device_api')
auth_blueprint.add_url_rule(
    '/device',
    view_func=device_view,
    methods=['GET']
)


class SmsAPI(MethodView):
    def get(self):
        data = request.headers
        phone_number = data.get('mobileNumber', None)
        if None in (phone_number,):
            return make_response(jsonify({'message': 'mobileNumber not found'})), 401

        print('going to send sms')
        pin = str(random.randrange(10000)).zfill(4)
        sms_info = {
            "country_code": "65",
            "phone_number": phone_number,
            "pin": pin
        }
        global_pin_store[phone_number] = pin

        res = requests.post(SMS_URL,
                            json=sms_info)
        # print('sent sms: %s' % res.text)
        print('sent sms: %s' % sms_info)

        responseObject = {
            'status': 'ok',
            'message': 'sms sent'
        }
        return make_response(jsonify(responseObject)), 201


sms_view = SmsAPI.as_view('sms_api')
auth_blueprint.add_url_rule(
    '/getsmstoken',
    view_func=sms_view,
    methods=['GET']
)


class DetectionAPIold(MethodView):
    def put(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                # print( 'auth_header: %s' % auth_header)
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                if user is None:
                    return make_response(jsonify({'message': 'put KO. user not found'})), 401

                detection_info = request.json
                detection_info['device_id'] = user.device_id
                print('detection_info: %s' % detection_info)
                res = requests.put(DETECTION_URL,
                                   json=detection_info)
                # return res
                return make_response(jsonify({'message': 'put detection OK'})), 201
                # return 'put detection ok'

            responseObject = {
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


class DetectionAPI(MethodView):
    def put(self):
        is_valid_token, user = check_valid_token()
        if not is_valid_token:
            return make_response(jsonify({'message': 'token issue'})), 401

        # detection_info = request.json
        detection_info = json.loads(request.data)
        detection_info['device_id'] = user.device_id
        print('detection_info: %s' % detection_info)
        res = requests.put(DETECTION_URL,
                           json=detection_info)
        return make_response(jsonify({'message': 'put detection OK'})), 201


detection_view = DetectionAPI.as_view('detection_api')
auth_blueprint.add_url_rule(
    '/detection',
    view_func=detection_view,
    methods=['PUT']
)


class ContacttraceAPI(MethodView):
    def get(self, device_id):
        is_valid_token, user = check_valid_token()
        if not is_valid_token:
            return make_response(jsonify({'message': 'token issue'})), 401

        data = request.args
        res = requests.get('/'.join([CONTACTTRACE_URL, device_id]), params=data)
        return make_response(jsonify(res.json())), res.status_code


contracttrace_view = ContacttraceAPI.as_view('contacttrace_api')
auth_blueprint.add_url_rule(
    '/contacttrace/<string:device_id>',
    view_func=contracttrace_view,
    methods=['GET']
)
