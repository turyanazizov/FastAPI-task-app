from peewee import Model, CharField, ForeignKeyField, DateTimeField, AutoField, TextField, SQL, IntegerField
from database import database
import json
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class CustomBaseModel(Model):
    class Meta:
        database = database

class User(CustomBaseModel):
    id = AutoField()
    username = CharField(unique=True, null=False)
    firstname = CharField( null=False)
    lastname = CharField( null=False)
    age = IntegerField( null=False)
    password = CharField(null=False)
    created_at = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])
    
    class Meta:
        database = database
        db_table = 'users'

    @classmethod
    def verify_password(cls, plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)
     
class Task(CustomBaseModel):
    id = AutoField()
    user = ForeignKeyField(User, backref='tasks')
    ip_address = CharField()
    data = TextField()
    created_at = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])

    def save_data(self, data):
        self.data = json.dumps(data)  # Serialize dict to JSON string
        self.save()

    def get_data(self):
        return json.loads(self.data)  # Deserialize JSON string back to Python dict


    class Meta:
        # This will create a foreign key constraint in the database
        database = database
        db_table = 'tasks'

class UserResponseModel(BaseModel):
    id: int
    firstname: str
    lastname: str
    age: int
    username: str

    class Config:
        from_attributes = True

class UserCreateRequest(BaseModel):
    firstname: str
    lastname: str
    age: int
    username: str
    password: str 

class LoginForm(BaseModel):
    username: str
    password: str

class UserUpdateRequest(BaseModel):
    username: str
    firstname: str
    lastname: str
    age: int

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
