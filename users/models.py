import random
from datetime import timedelta

from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractUser, AbstractBaseUser, UserManager
from django.core.validators import RegexValidator
from datetime import datetime
from shared.models import BaseModel

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

PHONE_EXPIRE = 2
EMAIL_EXPIRE = 5


class UserConfirmation(models.Model):
    TYPE_CHOISES = (
        (VIA_PHONE, VIA_PHONE),
        (VIA_EMAIL, VIA_EMAIL)
    )
    code = models.CharField(max_length=4)
    user = models.ForeignKey('users.User', on_delete=models.CASCADE)
    verify_type = models.CharField(max_length=30, choices=TYPE_CHOISES)
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

    AUTH_TYPE_CHOISES = (
        (VIA_EMAIL, VIA_EMAIL),
        (VIA_PHONE, VIA_PHONE),
        (VIA_USERNAME, VIA_USERNAME)
    )

    SEX_CHOISES = (
        (MALE, MALE),
        (FEMALE, FEMALE)
    )

    user_roles = models.CharField(max_length=30, choices=USER_ROLES, default=ORDINARY_USER)
    auth_type = models.CharField(max_length=30, choices=AUTH_TYPE_CHOISES, default=VIA_USERNAME)
    sex = models.CharField(max_length=20, choices=SEX_CHOISES, null=True)
    email = models.EmailField(unique=True, null=True)
    phone_number = models.CharField(max_length=12, unique=True, null=True, validators=[_validate_phone])
    bio = models.CharField(max_length=200, null=True)

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
