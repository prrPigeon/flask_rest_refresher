from flask import request, jsonify, make_response
from app import app, db
from app.models import User, Todo
import uuid 
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from app.decorators import token_required


@app.route('/user', methods=['GET'])
@token_required
def get_all_users():
    if not this_user.admin:
        return jsonify({'message': 'You are not admin, this page is no no'})
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        # new dict               # existing db
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users': output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
# this_user always must go in front off public id, because it will be invisible in other way.
def get_one_user(this_user, public_id):
    if not this_user.admin:
        return jsonify({'message': 'You are not admin, this page is no no'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found'})
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify({'user': user_data })

# next route will be for promotion user from admin=False, to admin=True
@app.route('/user', methods=['POST'])
@token_required
def create_user():
    if not this_user.admin:
        return jsonify({'message': 'You are not admin, this page is no no'})
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(this_user, public_id):
    if not this_user.admin:
        return jsonify({'message': 'You are not admin, this page is no no'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'NO that user maan.'})
    user.admin = True
    db.session.commit()
    return jsonify({'message': 'You are successfully promoted user to admin, niceee'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(this_user, public_id):
    if not this_user.admin:
        return jsonify({'message': 'You are not admin, this page is no no'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'NO that user maan.'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'you are delete that poor bastard!'})

@app.route('/login')
@token_required
def login():
    if not this_user.admin:
        return jsonify({'message': 'You are not admin, this page is no no'})
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})


@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(this_user):
    todos = Todo.query.filter_by(user_id=this_user.id).all()
    output = []
    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)
    return jsonify({'todos': output})

@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(this_user, todo_id):
    todo = Todo.query.filter_by(user_id=this_user.id, id=todo_id).first()
    if not todo:
        return jsonify({'message': 'There is no that specific todo!!!'})
    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete
    return jsonify(todo_data)

@app.route('/todo', methods=['POST'])
@token_required
def create_todo(this_user):
    data = request.get_json()
    new_todo = Todo(text=data['text'], complete=False, user_id=this_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'message': 'you are successfully created todo item'})

@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(this_user, todo_id):
    todo = Todo.query.filter_by(user_id=this_user.id, id=todo_id).first()
    if not todo:
        return jsonify({'message': 'There is no that specific todo!!!'})
         
    # sledeca lajna, samo ce da, prilikom dolaska na ovu rutu da prometni complete to True.
    todo.complete = True
    db.session.commit()
    return jsonify({'message': f'You are successfully completed todo with id {todo_id}'})

@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(this_user, todo_id):
    todo = Todo.query.filter_by(user_id=this_user.id, id=todo_id).first()
    if not todo:
        return jsonify({'message': 'There is no that specific todo!!!'})
    db.session.delete(todo)
    db.session.commit()
    return jsonify({'message': f'You are deleted todo with id {todo_id}'})