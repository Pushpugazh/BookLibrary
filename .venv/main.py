from fastapi import FastAPI, Depends, HTTPException, status, Path, Body
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import datetime

from database import engine, sessionLocal, Base
from models import User, Books, BookHistory, UserCreate, UserLogin, BookCreate, BookResponse, BookUpdate, BookReturn, HistoryCreate, HistoryResponse
from auth import hash_password, get_jwt_token, verify_password, get_current_user

app = FastAPI()

#Database Initialization
Base.metadata.create_all(bind=engine)

#Dependancy to get the database session
def get_db():
    db = sessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get('/')
async def default_route():
    return {"message" : "API is started"}

@app.post("/api/user/register")
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    try:
        password = hash_password(user.password)
        db_user = User(name=user.name, email=user.email, password=password, is_admin = user.is_admin)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

        return {"message": "User Registered Successfully"}

    except Exception as e:
        return HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")


@app.post("/api/user/login")
async def login_user(userlogin: UserLogin, db: Session = Depends(get_db)):

    try:
        user = db.query(User).filter(User.email == userlogin.email).first()

        if user is None or not verify_password(userlogin.password, user.password):
            if user is None:
                raise HTTPException(status_code=404, detail="User not registered", headers={"WWW-Authenticate": "Bearer realm='Restricted area'"})
            else:
                raise HTTPException(status_code=401, detail="Invalid Credentials", headers={"WWW-Authenticate": "Bearer realm='Restricted area'"})

        #JWT token encryption
        jwt_token = get_jwt_token(user.email, user.is_admin)

        return {"message": "User Login Successfull",
                "bearer_token": jwt_token}

    except HTTPException as e:
        return e

    except Exception as e:
        return HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

# only admin should access this api
@app.post("/api/book")
async def create_book(bookdetails : BookCreate, db: Session = Depends(get_db), current_user: tuple[str, bool] = Depends(get_current_user)):
    try:
        email, is_admin = current_user
        if not is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

        db_book = Books(title=bookdetails.title, description=bookdetails.description, author=bookdetails.author, count=bookdetails.count)
        db.add(db_book)
        db.commit()
        db.refresh(db_book)

        return {"message": "Book added to the DB"}

    except HTTPException as e:
        return e
    except Exception as e:
        return HTTPException(status_code=500, detail=f"Internal check Server Error: {str(e)}")

@app.get("/api/book", response_model=list[BookResponse])
async def get_all_books(db: Session = Depends(get_db), current_user: tuple[str, bool] = Depends(get_current_user)):
    booklist = db.query(Books).all()
    return booklist

@app.get("/api/book/{book_id}", response_model=BookResponse)
async def get_book_by_id(book_id: int = Path(...), db: Session = Depends(get_db), current_user: tuple[str, bool] = Depends(get_current_user)):
    try:
        book = db.query(Books).filter(Books.id == book_id).first()
        if not book:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="book not found")
        return book
    except HTTPException as http_exception:
        raise http_exception

@app.put("/api/book/{book_id}", response_model=None)
def update_book_by_id(book_id: int = Path(..., title="ID of the book to update"),
                      book_details: BookUpdate = Body(...),
                      db: Session = Depends(get_db),
                      current_user : tuple[str,bool] = Depends(get_current_user)
                      ):
    try:
        email, is_admin = current_user
        if not is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="Admin Access Required")

        book = db.query(Books).filter(Books.id == book_id).first()

        if not book:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Book not found")

        for field, value in book_details.dict().items():
            if value is not None:
                setattr(book, field, value)

        db.commit()
        db.refresh(book)
        updated_fields = {field: value for field, value in book_details.dict().items() if value is not None}

        return {"message": "Book updated successfully", "updated_book": updated_fields}

    except HTTPException as http_exception:
        raise http_exception

    except Exception as e:
        raise e


@app.post("/api/book/borrow/{book_id}", response_model=None)
async def borrow_book(book_id: int = Path(..., title="ID of the book to update"),
                      db: Session = Depends(get_db),
                      current_user : tuple[str,bool] = Depends(get_current_user)
                      ):

    try:
        email, is_admin = current_user
        if is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin cannot borrow book")

        book = db.query(Books).filter(Books.id == book_id).first()

        if not book:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Book not found")

        if book.count <= 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Book not available for borrowing")

        # book.borrower_id = email
        book.count -= 1
        db.commit()

        borrow_history_entry = BookHistory(book_id = book.id,
                                           user_id = email,
                                            action_type = "borrow"
                                           )
        db.add(borrow_history_entry)
        db.commit()

        return {"message": "Book has been borrowed",
                "borrowed book": book.title
                }

    except HTTPException as httpexception:
        return httpexception

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal Server Error: {str(e)}")


@app.put("/api/book/{book_id}/return")
async def return_book_by_id(book_id: int = Path(..., title="ID of the book to update"),
                            count: BookReturn = Body(...),
                            db: Session = Depends(get_db),
                            current_user: tuple[str, bool] = Depends(get_current_user)
                            ):
    try:
        email, is_admin = current_user
        if is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin cannot return book")

        book = db.query(Books).filter(Books.id == book_id).first()
        if not book:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Book not found")
        if count.return_count < 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Invalid return count. Must be a non-negative integer.")
        if count.return_count > 0:
            book.count += count.return_count
            db.commit()
            db.refresh(book)

        borrowed_book = db.query(BookHistory).filter(BookHistory.book_id == book_id).first()
        print("query is getting through")

        if not borrowed_book:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Book not borrowed by the user")
        print("Returning..")
        returned_datetime = datetime.utcnow()
        print("returned..")
        print(returned_datetime)
        borrowed_book.returned = f"returned on {returned_datetime}"

        db.commit()

        return {"message": f"{count.return_count} book(s) returned successfully", "book": book.title}

    except HTTPException as httpexception:
        return httpexception
    except Exception as e:
        return e
    return {"message" : "return apoi working"}

@app.delete("/api/book/{book_id}")
async def delete_book_by_id(book_id: int = Path(..., title="ID of the book to update"),
                            db: Session = Depends(get_db),
                            current_user: tuple[str, bool] = Depends(get_current_user)
                            ):
    try:
        email, is_admin = current_user
        if not is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin Access Required")

        book = db.query(Books).filter(Books.id == book_id).first()

        db.delete(book)
        db.commit()

        return {"message": "Book is deleted Successfully"}

    except HTTPException as e:
        return e

@app.delete("/api/books")
async def delete_all_books(db: Session = Depends(get_db),
                            current_user: tuple[str, bool] = Depends(get_current_user)
                            ):
    try:
        email, is_admin = current_user
        if not is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin Access Required")

        db.query(Books).delete()
        db.commit()

        return {"message": "All Books deleted Successfully"}

    except HTTPException as e:
        return e

@app.delete("/api/user/delete-all")
async def delete_all_users(db: Session = Depends(get_db),
                           current_user: tuple[str, bool] = Depends(get_current_user)
                           ):
    try:
        email, is_admin = current_user
        if not is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin Access Required")

        db.query(User).delete()
        db.commit()
        return {"message": "All users deleted successfully"}
    except Exception as e:
        # Handle exceptions appropriately
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/user/book", response_model=None)
async def get_user_books(db: Session = Depends(get_db),
                         current_user: tuple[str, bool] = Depends(get_current_user),
                         ):
    try:
        email, is_admin = current_user
        if is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin cannot borrow books")

        borrowed_books = (db.query(BookHistory, Books).join(Books).filter(
                    BookHistory.user_id == email,
                            BookHistory.returned == 'no').all()
                          )

        if not borrowed_books:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Books not borrowed by the user")

        book_ids = [{"title" : bookinstance.title,
                     "book_id" : historyentry.book_id,
                     "borrowed_on" : historyentry.action_data
                     } for historyentry, bookinstance in borrowed_books]

        return book_ids


    except HTTPException as httpexception:
        return httpexception

    except Exception as e:
        return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal Server Error: {str(e)}")


@app.get('/api/history', response_model= None)
async def retrieve_book_user_history(db: Session = Depends(get_db),
                                     user_details : HistoryCreate = Body(...),
                                     current_user: tuple[str, bool] = Depends(get_current_user)):
    try:
        _, is_admin = current_user
        if not is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin Access Required")

        if not user_details.email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required")
        # : email, book_title, type(borrow return), date
        history = db.query(BookHistory, Books).join(Books).filter(
                                                            BookHistory.user_id == user_details.email).all()
        if not history:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail= "user details not found")

        history_response = [
            {"user_email": user_details.email,
             "book_details": {
                 "title" : bookinstance.title,
                 "action_type" : historyinstance.action_type,
                 "returned" : historyinstance.returned
             }
             } for historyinstance, bookinstance in history
        ]

        return history_response

    except HTTPException as httpexception:
        return httpexception

    except Exception as e:
        return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal Server Error: {str(e)}")


'''
response model is for data validation and documention purpose (Pydantic - library model)

async method definition for methods handling i/o request operation
'''
