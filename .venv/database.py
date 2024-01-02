from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base


# Set up database connection
username = "root"
password = "DBpass123"
URL_DATABASE = f'mysql+pymysql://{username}:{password}@127.0.0.1:3306/pushpakdb'
engine = create_engine(URL_DATABASE)
# sessionLocal = sessionmaker(autocommit = False, autoflush=False, bind=engine)
sessionLocal = sessionmaker(bind=engine)


# Create User model
Base = declarative_base()


