import random
import uuid
from datetime import timedelta

from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractUser, AbstractBaseUser, UserManager
from django.core.validators import RegexValidator
from datetime import datetime
from shared.models import BaseModel
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

ORDINARY_USER, MANAGER, SUPER_ADMIN = (
    "ordinary_user",
    "manager",
    "super_admin"
)

VIA_EMAIL, VIA_PHONE, VIA_USERNAME = (
    "via_email",
    "via_phone",
    "via_username"

)

MALE, FEMALE = (
    "male",
    "female"
)

NEW, CODE_VERIFIED, DONE = (
    "NEW",
    "CODE_VERIFIED",
    "DONE"
)
PHONE_EXPIRE = 2
EMAIL_EXPIRE = 5


class UserConfirmation(models.Model):
    TYPE_CHOICES = (
        (VIA_PHONE, VIA_PHONE),
        (VIA_EMAIL, VIA_EMAIL)
    )
    user = models.ForeignKey('users.User', models.CASCADE, 'verify_codes')
    code = models.CharField(max_length=4)
    verify_type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user.__str__())

    def save(self, *args, **kwargs):
        if not self.pk:
            if self.verify_type == VIA_EMAIL:
                self.expiration_time = datetime.now() + timedelta(minutes=EMAIL_EXPIRE)
            else:
                self.expiration_time = datetime.now()
            super(UserConfirmation, self).save(*args, **kwargs)


class User(AbstractUser, BaseModel):
    _validate_phone = RegexValidator(
        regex=r"^998[0-9]{9}$",
        message="Example:"
    )

    USER_ROLES = (
        (ORDINARY_USER, ORDINARY_USER),
        (MANAGER, MANAGER),
        (SUPER_ADMIN, SUPER_ADMIN)
    )

    AUTH_TYPE_CHOICES = (
        (VIA_EMAIL, VIA_EMAIL),
        (VIA_PHONE, VIA_PHONE),
        (VIA_USERNAME, VIA_USERNAME)
    )

    SEX_CHOICES = (
        (MALE, MALE),
        (FEMALE, FEMALE)
    )
    AUTH_STATUS = (
        (NEW, NEW),
        (CODE_VERIFIED, CODE_VERIFIED),
        (DONE, DONE)
    )

    user_roles = models.CharField(max_length=30, choices=USER_ROLES, default=ORDINARY_USER)
    auth_type = models.CharField(max_length=30, choices=AUTH_TYPE_CHOICES, default=VIA_USERNAME)
    auth_status = models.CharField(max_length=35, choices=AUTH_STATUS, default=NEW)
    sex = models.CharField(max_length=20, choices=SEX_CHOICES, null=True, blank=True)
    email = models.EmailField(unique=True, null=True)
    phone_number = models.CharField(max_length=12, unique=True, null=True, blank=True, validators=[_validate_phone])
    bio = models.CharField(max_length=200, null=True, blank=True)

    objects = UserManager()

    def __str__(self):
        return self.username

    @property
    def ful_name(self):
        return f"{self.first_name} {self.last_name}"

    def create_verify_code(self, verify_type):
        code = "".join([str(random.randint(0, 100) % 10) for _ in range(4)])
        UserConfirmation.objects.create(
            user_id=self.id,
            verify_type=verify_type,
            code=code
        )
        return code

    def check_username(self):
        if not self.username:
            temp_username = f'DemoProject-{uuid.uuid4().__str__().split("-")[-1]}'
            while User.objects.filter(username=temp_username):
                temp_username = f'{temp_username}{random.randint(0, 9)}'
            self.username = temp_username

    def check_email(self):
        if self.email:
            normalized_email = self.email.lower()
            self.email = normalized_email

    def check_pass(self):
        if not self.password:
            temp_password = f'password-{uuid.uuid4().__str__().split("-")[-1]}'
            self.password = temp_password

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sha256'):
            self.set_password(self.password)

    def tokens(self):
        refresh = RefreshToken().for_user(self)
        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        }

    def save(self, *args, **kwargs):
        if not self.pk:
            self.clean()
        super(User, self).save(*args, **kwargs)

    def clean(self):
        self.check_email()
        self.check_username()
        self.check_pass()
        self.hashing_password()
