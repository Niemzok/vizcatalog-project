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
    description = Column(String(800))
    user_id = Column(Integer,ForeignKey('user.id'), nullable=False)
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'description'  : self.description,
           'creator'      : self.user.name
       }

class Viz(Base):
    __tablename__='viz'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(String(800))
    link = Column(String(250), nullable=False)
    author_name = Column(String(250), nullable=False)
    height = Column(Integer)
    width = Column(Integer)
    user_id = Column(Integer,ForeignKey('user.id'), nullable=False)
    user = relationship(User)
    category_id = Column(Integer,ForeignKey('category.id'), nullable=False)
    category = relationship(Category)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'description'  : self.description,
           'link'         : self.link,
           'author_name'  : self.author_name,
           'height'       : self.height,
           'width'        : self.width,
           'creator'      : self.user.name,
           'category'     : self.category.name
       }

engine = create_engine('sqlite:///vizzes.db')


Base.metadata.create_all(engine)
