from flask import request, jsonify, session
from app import mongo, app
from models import UserSchema, AssignmentSchema
from marshmallow import ValidationError
from bson import ObjectId
from pymongo.errors import PyMongoError
from datetime import datetime, timezone
from functools import wraps


def login_required(f):
    """
    Decorator to enforce login requirement for a Flask view function.

    This decorator checks if the user is logged in by verifying the presence
    of 'user_id' in the session. If the user is not logged in, it returns a
    JSON response indicating that login is required with a 401 Unauthorized status.

    Parameters:
        f (function): The view function to be wrapped by the decorator.

    Returns:
        function: The wrapped view function that requires authentication.

    Raises:
        - 401 Unauthorized: If the user is not logged in.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Login required'}), 401
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    """
    Decorator to enforce admin access requirement for a Flask view function.

    This decorator checks if the user is logged in and has admin privileges
    by verifying the presence of 'user_id' in the session and that
    'is_admin' is set to True. If the user is not an admin, it returns a
    JSON response indicating that admin access is required with a 403 Forbidden status.

    Parameters:
        f (function): The view function to be wrapped by the decorator.

    Returns:
        function: The wrapped view function that requires admin privileges.

    Raises:
        - 403 Forbidden: If the user is not logged in or does not have admin access.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or not session['is_admin']:
            return jsonify({'success': False, 'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return wrapper


@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user.

    This POST endpoint registers a new user within the `users` collection.
    It accepts the user's username, password, and an optional `is_admin` flag
    indicating whether the user should be an admin. The endpoint validates the
    provided data and checks if the username already exists. If successful,
    the user information is saved in the database.

    Request JSON Body:
    {
        "username": "string",         # Required, the username for the new user
        "password": "string",         # Required, the password for the new user
        "is_admin": "boolean"         # Optional, default is False; indicates if the user is an admin
    }

    Returns:
        JSON Response:
            - Success:
                Status Code: 201
                {
                    "success": True,
                    "message": "User registered successfully"
                }
            - Failure:
                Status Code: 400
                {
                    "success": False,
                    "message": "Validation error messages"
                }
                Status Code: 409
                {
                    "success": False,
                    "message": "Username already exists"
                }

    Raises:
        - 400 Bad Request: If the provided data fails validation or if the username already exists.
        - 409 Conflict: If the provided username already exists.
    """
    data = request.get_json()

    try:
        UserSchema().load(data)
    except ValidationError as err:
        return jsonify({'success': False, 'message': err.messages}), 400

    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)

    if mongo.db.users.find_one({'username': username}):
        return jsonify({'success': False, 'message': 'Username already exists'}), 409

    mongo.db.users.insert_one({
        'username': username,
        'password': password,
        'is_admin': is_admin
    })
    return jsonify({'success': True, 'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    """
    Authenticate a user and initiate a session.

    This POST endpoint allows a registered user to log in by providing
    their username and password. If the credentials are correct, a session
    is created for the user, storing their user ID, username, and admin status.

    Request JSON Body:
    {
        "username": "string",         # Required, the username of the user
        "password": "string"          # Required, the password of the user
    }

    Returns:
        JSON Response:
            - Success:
                Status Code: 200
                {
                    "success": True,
                    "message": "Logged in successfully"
                }
            - Failure:
                Status Code: 400
                {
                    "success": False,
                    "message": "Validation error messages"
                }
                Status Code: 401
                {
                    "success": False,
                    "message": "Invalid credentials"
                }

    Raises:
        - 400 Bad Request: If the provided data fails validation.
        - 401 Unauthorized: If the username or password is incorrect.
    """
    data = request.get_json()

    try:
        UserSchema().load(data)
    except ValidationError as err:
        return jsonify({'success': False, 'message': err.messages}), 400

    username = data.get('username')
    password = data.get('password')

    user = mongo.db.users.find_one({'username': username, 'password': password})
    if user:
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        session['is_admin'] = user['is_admin']
        return jsonify({'success': True, 'message': 'Logged in successfully'}), 200

    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401


@app.route('/logout', methods=['POST'])
def logout():
    """
    Log out the current user.

    This POST endpoint logs out the current user by clearing their session data.
    It removes any stored information (user_id, username and admin status) from
    the session, effectively ending the user's session.

    Returns:
        JSON Response:
            - Success:
                Status Code: 200
                {
                    "success": True,
                    "message": "Logged out successfully"
                }
    """
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200


@app.route('/upload', methods=['POST'])
@login_required
def upload_assignment():
    """
    Submit an assignment for review.

    This POST endpoint allows authenticated users to upload an assignment.
    The submitted data includes the task description and the admin who will
    review the assignment. The endpoint stores the assignment in the `assignments`
    collection with a status of "pending" and a timestamp.

    Request JSON Body:
    {
        "task": "string",        # Required, description of the assignment task
        "admin": "string"        # Required, the username of the admin to review the assignment
    }

    Returns:
        JSON Response:
            - Success:
                Status Code: 201
                {
                    "success": True,
                    "message": "Assignment submitted successfully"
                }
            - Failure:
                Status Code: 400
                {
                    "success": False,
                    "message": "Validation error messages / Admin does not exist"
                }
                Status Code: 409
                {
                    "success": False,
                    "message": "Assignment submission failed"
                }
                Status Code: 500
                {
                    "success": False,
                    "message": "An error occurred: <Error details>"
                }

    Raises:
        - 400 Bad Request: If the provided data fails validation / If the admin does not exist.
        - 409 Conflict: If the assignment submission fails for any reason.
        - 500 Internal Server Error: If there is an error during the database operation.
    """
    username = session['username']
    data = request.get_json()

    try:
        AssignmentSchema().load(data)
    except ValidationError as err:
        return jsonify({'success': False, 'message': err.messages}), 400

    task = data.get('task')
    admin = data.get('admin')

    if mongo.db.assignments.find_one({'admin': admin}) is None:
        return jsonify({'success': False, 'message': 'Admin does not exist'}), 400

    try:
        result = mongo.db.assignments.insert_one({'username': username,
                                                  'task': task,
                                                  'admin': admin,
                                                  'status': 'pending',
                                                  'timestamp': datetime.now(tz=timezone.utc)})

        if result.inserted_id:
            return jsonify({'success': True, 'message': 'Assignment submitted successfully'}), 201
        else:
            return jsonify({'success': False, 'message': 'Assignment submission failed'}), 409
    except PyMongoError as e:
        # Handle potential errors during the insert operation
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500


@app.route('/admins', methods=['GET'])
@login_required
def get_admins():
    """
    Retrieve a list of admin usernames.

    This GET endpoint returns a list of all users in the system who have
    admin privileges. The endpoint requires the user to be logged in.

    Returns:
        JSON Response:
            Status Code: 200
            {
                "admins": ["admin_username_1", "admin_username_2", ...]
            }
    """
    admins = mongo.db.users.find({'is_admin': True})
    return jsonify([admin['username'] for admin in admins]), 200


@app.route('/assignments', methods=['GET'])
@login_required
@admin_required
def get_assignments():
    """
    Retrieve assignments for the logged-in admin.

    This GET endpoint returns a list of assignments that are associated
    with the logged-in admin. The endpoint requires the user to be logged in
    and have admin privileges to access this information.

    Returns:
        JSON Response:
            - Success:
                Status Code: 200
                {
                    "assignments": [
                        {
                            "username": "string",  # The username of the user who submitted the assignment
                            "task": "string",      # The description of the assignment task
                            "status": "string",    # The current status of the assignment (e.g., pending, completed)
                            "timestamp": "datetime" # The timestamp of when the assignment was submitted
                        },
                        ...
                    ]
                }
            - Failure:
                Status Code: 403
                {
                    "success": False,
                    "message": "Permission denied"
                }

    Raises:
        - 403 Forbidden: If the logged-in user is not an admin.
    """
    if session['is_admin'] is not True:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    admin_username = session['username']
    assignments = mongo.db.assignments.find({'admin': admin_username})
    return jsonify([{
        'username': assignment['username'],
        'task': assignment['task'],
        'status': assignment['status'],
        'timestamp': assignment['timestamp']
    } for assignment in assignments]), 200


@app.route('/assignments/<assignment_id>/accept', methods=['POST'])
@login_required
@admin_required
def accept_assignment(assignment_id):
    """
    Accept an assignment and update its status.

    This POST endpoint allows an admin to accept a specific assignment by
    updating its status to "accepted". The endpoint requires the user to be
    logged in and have admin privileges.

    Path Parameters:
        assignment_id (string): The ID of the assignment to be accepted.

    Returns:
        JSON Response:
            - Success:
                Status Code: 200
                {
                    "success": True,
                    "message": "Assignment accepted"
                }
            - Failure:
                Status Code: 400
                {
                    "success": False,
                    "message": "Invalid assignment ID"
                }
                Status Code: 404
                {
                    "success": False,
                    "message": "Assignment not found"
                }
                Status Code: 500
                {
                    "success": False,
                    "message": "An error occurred: <Error details>"
                }

    Raises:
        - 403 Forbidden: If the logged-in user is not an admin.
        - 400 Bad Request: If the provided assignment ID is invalid.
        - 404 Not Found: If no assignment with the given ID exists.
        - 500 Internal Server Error: If there is an error during the database operation.
    """
    if session['is_admin'] is not True:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    if not ObjectId.is_valid(assignment_id):
        return jsonify({'success': False, 'message': 'Invalid assignment ID'}), 400

    assignment = mongo.db.assignments.find_one({'_id': ObjectId(assignment_id)})
    if not assignment:
        return jsonify({'success': False, 'message': 'Assignment not found'}), 404

    try:
        result = mongo.db.assignments.update_one({'_id': ObjectId(assignment_id)},
                                        {'$set': {'status': 'accepted'}})

        if result.matched_count > 0:
            return jsonify({'success': True, 'message': 'Assignment accepted'}), 200
        else:
            return jsonify({'success': False, 'message': 'Assignment not found'}), 404
    except PyMongoError as e:
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500


@app.route('/assignments/<assignment_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_assignment(assignment_id):
    """
    Reject an assignment and update its status.

    This POST endpoint allows an admin to reject a specific assignment by
    updating its status to "rejected". The endpoint requires the user to be
    logged in and have admin privileges.

    Path Parameters:
        assignment_id (string): The ID of the assignment to be rejected.

    Returns:
        JSON Response:
            - Success:
                Status Code: 200
                {
                    "success": True,
                    "message": "Assignment rejected"
                }
            - Failure:
                Status Code: 400
                {
                    "success": False,
                    "message": "Invalid assignment ID"
                }
                Status Code: 404
                {
                    "success": False,
                    "message": "Assignment not found"
                }
                Status Code: 500
                {
                    "success": False,
                    "message": "An error occurred: <Error details>"
                }

    Raises:
        - 403 Forbidden: If the logged-in user is not an admin.
        - 400 Bad Request: If the provided assignment ID is invalid.
        - 404 Not Found: If no assignment with the given ID exists.
        - 500 Internal Server Error: If there is an error during the database operation.
    """
    if session['is_admin'] is not True:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    if not ObjectId.is_valid(assignment_id):
        return jsonify({'success': False, 'message': 'Invalid assignment ID'}), 400

    assignment = mongo.db.assignments.find_one({'_id': ObjectId(assignment_id)})
    if not assignment:
        return jsonify({'success': False, 'message': 'Assignment not found'}), 404

    try:
        result = mongo.db.assignments.update_one({'_id': ObjectId(assignment_id)},
                                        {'$set': {'status': 'rejected'}})

        if result.matched_count > 0:
            return jsonify({'success': True, 'message': 'Assignment rejected'}), 200
        else:
            return jsonify({'success': False, 'message': 'Assignment not found'}), 404
    except PyMongoError as e:
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500