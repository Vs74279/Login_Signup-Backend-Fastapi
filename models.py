# models.py
 
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
 
Base = declarative_base()
 
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    firstName = Column(String)
    lastName = Column(String)
    email = Column(String, unique=True, index=True)
    phone = Column(String)
    password = Column(String)
    qualification = Column(String)