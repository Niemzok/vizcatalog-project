from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__='user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250), nullable=False)

class Category(Base):
    __tablename__='category'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    descrption = Column(String(800))
    user_id = Column(Integer,ForeignKey('user.id'), nullable=False)
    user = relationship(User)

class Viz(Base):
    __tablename__='viz'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    descrption = Column(String(800))
    link = Column(String(250), nullable=False)
    author_name = Column(String(250), nullable=False)
    user_id = Column(Integer,ForeignKey('user.id'), nullable=False)
    user = relationship(User)
    category_id = Column(Integer,ForeignKey('category.id'), nullable=False)
    category = relationship(Category)

engine = create_engine('sqlite:///vizzes.db')


Base.metadata.create_all(engine)
