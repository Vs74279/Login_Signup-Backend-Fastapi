from pydantic import BaseModel
 
class UserBase(BaseModel):
    email: str
 
class UserCreate(UserBase):
    firstName: str
    lastName: str
    phone: str
    password: str
    qualification: str
 
class UserLogin(BaseModel):
    email: str
    password: str   