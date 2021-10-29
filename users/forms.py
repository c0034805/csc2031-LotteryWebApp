import re

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Required, Email, ValidationError, Length, EqualTo


def character_check(form, field):
    invalid_chars = "* ? ! ' ^ + % & / ( ) = } ] [ { $ # @ < >".split()

    if 1 in [c in invalid_chars for c in field.data]:
        raise ValidationError(
            "Special characters are not allowed in this field."
        )


class RegisterForm(FlaskForm):

    def validate_phone(self, phone):
        p = re.compile(r'\d{4}-\d{3}-\d{4}')
        if not p.match(self.phone.data):
            raise ValidationError(
                "Phone number must be of the format XXXX-XXX-XXXX."
            )

    def validate_password(self, password):
        p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
        spc = re.compile('[!"£$%^&*()_\\-=+/\\\,.><`#~¬]')
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
        Length(min=32, max=32, message="PIN key must be exactly 32 characters long.")
    ])
    submit = SubmitField(validators=[
        Required()
    ])

