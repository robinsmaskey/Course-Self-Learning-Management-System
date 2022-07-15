from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.validators import RegexValidator
from django.conf import settings


# Create your models here.
class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, username, password, **extra_fields):
        """
        Create and save a user with the given email, and password.
        """
        email = self.normalize_email(email)
        user = self.model(email=email, username=username,**extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_user(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, username, password, **extra_fields)

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self._create_user(email, username, password, **extra_fields)

class PortalUser(AbstractUser):
    alphanumeric = RegexValidator(r'^[0-9a-zA-Z]*$', 'Only alphanumeric characters are allowed.')
    USER_TYPES = (
        ('CHILD', 'child'),
        ('GUARDIAN', 'guardian'),
    )
    username = models.CharField(max_length=100,validators=[alphanumeric], unique=True, blank=False, null=True)
    full_name = models.CharField(max_length=100)

    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=16)
    address = models.CharField(max_length=64)
    user_type = models.CharField(choices=USER_TYPES, max_length=64)
    is_verified = models.BooleanField(default=False)
    image = models.ImageField(null=True, blank=True, upload_to='media/images/user/')
    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def get_full_name(self):
        return self.full_name

    def __str__(self):
        return self.email

# class User(AbstractUser):
#       CHILD = 2
      
#       ROLE_CHOICES = (
#           (CHILD, 'Child'),
#       )
#       role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, blank=True, null=True)
      # You can create Role model separately and add ManyToMany if user has more than one role

# class Child(models.Model):

#     user = models.ForeignKey(settings.AUTH_USER_MODEL2, on_delete=models.CASCADE)
#     class Meta:
#         permissions = (
#                        ("view_child", "view child"),
#                        ("find_child", "can find child"),
                    #   )
