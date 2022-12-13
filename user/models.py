from django.db import models
import uuid

# Create your models here.
class BaseModel(models.Model):
    uuid=models.UUIDField(primary_key=True,default=uuid.uuid4())

    class Meta:
        abstract=True


class User(BaseModel):
    userName=models.CharField(max_length=100)