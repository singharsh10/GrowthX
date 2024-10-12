from marshmallow import Schema, fields, validate


class UserSchema(Schema):
    """
    Schema for user data validation.

    Usage:
        This schema is typically used for validating input data when creating new users
        or managing existing ones.

    It checks for the presence and correctness of the following fields:

    Fields:
        - username (str, required): The username of the user.
          Must be a non-empty string with a minimum length of 1 character.
        - password (str, required): The password of the user.
          Must be a string with a minimum length of 3 characters.
        - is_admin (bool, optional): A flag indicating if the user is an admin.
          Defaults to False if not provided. Must be either True or False.

    Raises:
        - ValidationError: If the input data does not match the required format.
    """
    username = fields.Str(required=True, validate=validate.Length(min=1))
    password = fields.Str(required=True, validate=validate.Length(min=3))
    is_admin = fields.Bool(required=False, default=False, validate=validate.OneOf([True, False]))


class AssignmentSchema(Schema):
    """
    Schema for assignment data validation.

    Usage:
        This schema is typically used for validating input data when creating or updating assignments.

    It checks for the presence and correctness of the following fields:

    Fields:
        - username (str, optional): The username of the user who submitted the assignment.
          Must be a non-empty string if provided.
        - task (str, required): The description of the task.
          Must be a non-empty string with a minimum length of 1 character.
        - admin (str, required): The username of the admin responsible for reviewing the assignment.
          Must be a non-empty string with a minimum length of 1 character.
        - status (str, optional): The status of the assignment.
          Must be one of 'pending', 'accepted', or 'rejected' if provided.
        - timestamp (datetime, optional): The timestamp of when the assignment was submitted.
          If not provided, it is typically set by the server during assignment creation.

    Raises:
        - ValidationError: If the input data does not match the required format.
    """
    username = fields.Str(required=False, validate=validate.Length(min=1))
    task = fields.Str(required=True, validate=validate.Length(min=1))
    admin = fields.Str(required=True, validate=validate.Length(min=1))
    status = fields.Str(required=False, validate=validate.OneOf(['pending', 'accepted', 'rejected']))
    timestamp = fields.DateTime(required=False)