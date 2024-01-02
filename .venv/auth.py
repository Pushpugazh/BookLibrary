from datetime import datetime, timedelta
# import datetime
import jwt
from jwt import PyJWTError
# from jose import JWTError
from passlib.hash import bcrypt
from fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer



# JWT authentication settings
SECRET_KEY = "keytoencode123"
ALGORITHM = 'HS256'
EXPIRATION_TIME = 2


def get_jwt_token(subemail, is_admin=False):

    expiration_time = datetime.utcnow() + timedelta(minutes=EXPIRATION_TIME)
    to_encode = {"sub": subemail, "expire": expiration_time.strftime('%Y-%m-%dT%H:%M:%S'), "is_admin": is_admin}

    encoded_token = jwt.encode(to_encode, SECRET_KEY, ALGORITHM)

    return  encoded_token

def hash_password(password):
    return bcrypt.hash(password)

def verify_password(loginpass, hashedpass):
    return bcrypt.verify(loginpass, hashedpass)

#decode JWT to get the current user

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")   # this returns a bearer token

def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        is_admin : bool = payload.get("is_admin", False)
        expire: str = payload.get("expire")

        if expire is None or datetime.strptime(expire, '%Y-%m-%dT%H:%M:%S') <= datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

    except PyJWTError:
        raise credential_exception

    return email, is_admin
    print("returning both {} & {}".format(email, is_admin))

