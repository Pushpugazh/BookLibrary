from sqlalchemy import Boolean, Column, Integer, String, Sequence, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from database import Base


# schema of users table
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, Sequence("user_id_seq"), primary_key=True, index=True)
    name = Column(String(255), index=True)
    email = Column(String(255), unique=True, index=True)
    password = Column(String(255))
    is_admin = Column(Boolean, default=False)
    # created_at = Column(DateTime(timezone=True), server_default=func.now())
    books = relationship('Books', back_populates='borrower', foreign_keys='Books.borrower_id')
    borrowed_books = relationship('Books', back_populates='borrower', foreign_keys='Books.borrower_id',
                                  overlaps='books')

#schema of Books table
class Books(Base):
    __tablename__ = "books"

    id = Column(Integer, Sequence("books_id_seq"), primary_key=True, index=True)
    title = Column(String(255))
    description = Column(String(255))
    author = Column(String(255))
    count = Column(Integer)
    # borrower_id = Column(String(255), nullable=True)
    borrower_id = Column(Integer, ForeignKey('users.id'))
    borrower = relationship('User', back_populates='books')

#pydantic model
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    is_admin: Optional[bool] = None

#pydantic model for user login request
class UserLogin(BaseModel):
    email: EmailStr
    password: str

# pydantic model for create book api
class BookCreate(BaseModel):
    title: str
    description: str
    author : str
    count : int

class BookUpdate(BaseModel):
    title: Optional[str] = Field(None)
    description: Optional[str] = Field(None)
    author: Optional[str] = Field(None)
    count: Optional[int] = Field(None)

class BookResponse(BookCreate):
    id : int

class BookReturn(BaseModel):
    return_count : int

