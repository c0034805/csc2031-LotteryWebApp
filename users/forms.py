# IMPORTS
import re

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Required, Email, ValidationError, Length, EqualTo


# character validation function
def character_check(form, field):
    # characters to check for
    invalid_chars = "* ? ! ' ^ + % & / ( ) = } ] [ { $ # @ < >".split()

    # if any of the characters above are not in the field data raise validation error
    if 1 in [c in invalid_chars for c in field.data]:
        raise ValidationError(
            "Special characters are not allowed in this field."
        )


class RegisterForm(FlaskForm):
    # FIELD VALIDATION FUNCTIONS
    # phone field format validation
    def validate_phone(self, phone):
        # 4 digits, dash, 3 digits, dash, 4 digits
        p = re.compile(r'\d{4}-\d{3}-\d{4}')

        # if the field data do not match the format raise validation error
        if not p.match(self.phone.data):
            raise ValidationError(
                "Phone number must be of the format XXXX-XXX-XXXX."
            )

    # password field format validation
    def validate_password(self, password):
        # a digit, an uppercase letter, a lowercase letter
        p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
        # a special character
        spc = re.compile('[!"£$%^&*()_\\-=+/\\\,.><`#~¬]')

        # if password does not contain a digit, an uppercase leter, a lowercase letter or a special character
        if not p.match(self.password.data) or spc.search(self.password.data) is None:
            raise ValidationError(
                "Password must contain at least 1 digit, 1 lowercase letter, one uppercase letter and a special "
                "character.")

    email = StringField(validators=[
        Required(),
        Email()
    ])
    firstname = StringField(validators=[
        Required(),
        character_check
    ])
    lastname = StringField(validators=[
        Required(),
        character_check
    ])
    phone = StringField(validators=[
        Required()
    ])
    password = PasswordField(validators=[
        Required(),
        Length(min=6, max=12, message="Password must be between 6 and 12 characters long."),
        EqualTo('confirm_password', message="Passwords must match.")
    ])
    confirm_password = PasswordField(validators=[
        Required()
    ])
    pin_key = StringField(validators=[
        Required(),
        Length(min=32, max=32, message="PIN key must be exactly 32 characters long."),
        character_check
    ])
    submit = SubmitField(validators=[
        Required()
    ])


class LoginForm(FlaskForm):
    email = StringField(validators=[
        Required(),
        Email()
    ])
    password = PasswordField(validators=[
        Required()
    ])
    pin = StringField(validators=[
        Required()
    ])
    submit = SubmitField()
