from fastapi_mail import ConnectionConfig,FastMail,MessageSchema,MessageType
from sqlalchemy import create_engine,TIMESTAMP,Column,String,text,Boolean,Integer
from sqlalchemy.orm import Session,sessionmaker
from fastapi import Depends,status,FastAPI,Form,Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.declarative import as_declarative
from fastapi.templating import Jinja2Templates
from starlette.responses import JSONResponse
from fastapi.exceptions import HTTPException
from typing import Any,List,Optional,Union
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from datetime import datetime,timedelta
from jose import jwt
import uuid





SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
#SQLALCHEMY_DATABASE_URL = "mysql+pymysql://root:@localhost:3307/test"

POOL_SIZE: int = 20
POOL_RECYCLE: int = 3600
POOL_TIMEOUT: int = 15
MAX_OVERFLOW: int = 2
CONNECT_TIMEOUT: int = 60
connect_args = {"connect_timeout":CONNECT_TIMEOUT}


MAIL_USERNAME: str = 'dev.aiti.com.gh@gmail.com'
MAIL_PASSWORD: str = 'uefuovgtfwyfgskv'
MAIL_FROM: str = 'dev.aiti.com.gh@gmail.com'
MAIL_PORT: int = 587
MAIL_SERVER: str = 'smtp.gmail.com'
MAIL_STARTTLS: bool = True
MAIL_SSL_TLS: bool = False
USE_CREDENTIALS: bool = True
VALIDATE_CERTS: bool = True

EMAIL_CODE_DURATION_IN_MINUTES: int = 15
ACCESS_TOKEN_EXPIRE_MINUTES: int = 10
REFRESH_TOKEN_DURATION_IN_MINUTES: int = 600
PASSWORD_RESET_TOKEN_DURATION_IN_MINUTES: int = 15
ACCOUNT_VERIFICATION_TOKEN_DURATION_IN_MINUTES: int = 15
JWT_SECRET_KEY : str = "7b6c506ee07337cc3d02536d5119c4b2"
ALGORITHM: str = "HS256"



engine = create_engine(SQLALCHEMY_DATABASE_URL, 
                       pool_size=POOL_SIZE, 
                       pool_recycle=POOL_RECYCLE,
                       pool_timeout=POOL_TIMEOUT, 
                       max_overflow=MAX_OVERFLOW)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


@as_declarative()
class Base:
    id: Any


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()




class User(Base):
    __tablename__='users'
    id=Column(Integer, primary_key=True, index=True)
    username=Column(String(255),nullable=True)
    email=Column(String(255),nullable=True,unique=True)
    phone=Column(String(255),nullable=True)
    password=Column(String(255),nullable=True)
    reset_password_token = Column(String(255), nullable=True)
    is_active = Column(Boolean, nullable=True, default=False)
    created_at = Column(TIMESTAMP, nullable=True,server_default=text("CURRENT_TIMESTAMP"))


Base.metadata.create_all(engine);





class SignUser(BaseModel):
    username: str
    email: str
    phone: str


    class Config:
        orm_mode = True







# Authentication module for admins and users
app=FastAPI(docs_url="/")
templates = Jinja2Templates(directory="templates")






class Hasher():
    
    #get user by email function
    @staticmethod
    def get_user_by_email(username: str, db: Session):
        user = db.query(User).filter_by(email=username).first()
        if not user:
            return False
        return user


    #function to verify password
    @staticmethod 
    def verify_password(plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)


    #authenticate_user function
    @staticmethod
    def authenticate_user(username: str, password: str, db: Session):
            db_user = Hasher.get_user_by_email(username=username, db=db)
            if not db_user:
                return False
            if not Hasher.verify_password(password, db_user.password):
                return False 
            return db_user



    # Generate access token function
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt












@app.get('/')
async def welcome():
    return {'message':'Hello world'}




    #Generate generate_reset_password_token function

def generate_reset_password_token(expires: int = None):
        if expires is not None:
            expires = datetime.utcnow() + expires
        else:
            expires = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode = {"exp": expires}
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
        return encoded_jwt


@app.post("/signup")
async def signup(signup: Union[SignUser, List[SignUser]], db: Session = Depends(get_db)):
    
    db_query = db.query(User).filter(
            User.email == signup.email
        ).filter(
            User.phone == signup.phone
        ).first()

    if db_query is not None:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER,
           detail="User with email or phone number already exists")

    new_user = User(username=signup.username, email=signup.email, 
                    phone=signup.phone,reset_password_token= generate_reset_password_token())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    await sendemailtonewusers([signup.email], new_user)
    return new_user














pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.post("/update")
def update(token: str, password: str = Form(...), db: Session = Depends(get_db)):
    data = db.query(User).filter(User.reset_password_token == token).update({
        User.reset_password_token : None,
        User.password : pwd_context.hash(password),
        User.is_active: True
        }, synchronize_session=False)
    db.flush()
    db.commit()

    if not data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
            detail="password not reset")

    return "password reset Successfully"




















## function to authenticate all admin and users
@app.post('/token')
async def admin_and_user_authentication(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    
    data = Hasher.authenticate_user(form_data.username, form_data.password, db=db)
    if not data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                        detail="Invalid login credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = Hasher.create_access_token(data={"email": data.email}, expires_delta=access_token_expires)

    if data.is_active != True:
        raise HTTPException(status_code=400, detail="you account is not active")
    
    return {
        "access_token":access_token,
        "token_type": "bearer",
        "user": data
        }

































class EmailSchema(BaseModel):
    email: List[EmailStr]






conf = ConnectionConfig(
    MAIL_USERNAME = MAIL_USERNAME,
    MAIL_PASSWORD = MAIL_PASSWORD,
    MAIL_FROM =  MAIL_FROM,
    MAIL_PORT = MAIL_PORT,
    MAIL_SERVER = MAIL_SERVER,
    MAIL_STARTTLS = MAIL_STARTTLS,
    MAIL_SSL_TLS = MAIL_SSL_TLS,
    USE_CREDENTIALS = USE_CREDENTIALS,
    VALIDATE_CERTS = VALIDATE_CERTS
)




# function to send email notification to new user
async def sendemailtonewusers(email: EmailSchema, instance: User):

    reset = str(instance.reset_password_token)

    new_reset = ""
    for i in reset:
        if(i not in "'"):
            new_reset = new_reset + i

    html = f"""
            <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>GI-KACE SMART CONFERENCE APP</title>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            background-color: #f5f5f5;
                            margin: 0;
                            padding: 0;
                        }}
        
                            .container {{
                                max-width: 600px;
                                margin: 0 auto;
                                padding: 20px;
                                background-color: #ffffff;
                                box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.1);
                                border-radius: 5px;
                                margin-top: 20px;
                                text-align: center;
                            }}
                            
                            h2, p {{
                                margin: 0;
                                margin-bottom: 12px;
                            }}
                            
                            h2 {{
                                font-size: 24px;
                                font-weight: bold;
                            }}
                            
                            p {{
                                font-size: 16px;
                                line-height: 1.5;
                            }}
                            
                            .welcome-section {{
                                margin-bottom: 24px;
                            }}
                            
                            .thankyou-section {{
                                margin-bottom: 24px;
                            }}
                            
                            .btn {{
                                display: inline-block;
                                margin-top: 12px;
                                padding: 12px 24px;
                                background-color: #1abc9c;
                                color: #ffffff;
                                text-decoration: none;
                                border-radius: 4px;
                            }}
                            
                            .btn span {{
                                color: #000000;
                            }}
                        </style>
                    </head>
                    <body>
    <div class="container">
        <div class="welcome-section">
            <h2>Hi {instance.username},</h2>
            <p>Thank you for signing up</p>
        </div>
        <div class="thankyou-section">
            <p>Please change your password to access the application.</p>
            <a class="btn" href="http://localhost:8000/reset-password?token={new_reset}">Reset Password <span>&#9658;</span></a>
            <p>If you're having trouble clicking the "Reset Password" button, copy and paste the following URL into your web browser:</p>

            
            <p>http://localhost:8000/reset-password?token={new_reset}</p>
        </div>
    </div>
</body>
</html>
"""


    message = MessageSchema(
        subject= "TESTING APP",
        recipients=email,
        body=html,
        subtype=MessageType.html)

    fm = FastMail(conf)
    await fm.send_message(message)
    return JSONResponse(status_code=200, content={"message": "email has been sent successfully"})













@app.get("/reset-password", response_class=HTMLResponse)
def reset_password(request: Request, token: str, db: Session = Depends(get_db)):
    user_db_data = db.query(User).filter(User.reset_password_token == token).first()
    if not user_db_data:
        return """
                <h1 style="color:red,text-align:center;">Invalid token</h1>
                """

    html = f"""
            
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>RESET PASSWORD</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" integrity="sha384-xOolHFLEh07PJGoPkLv1IbcEPTNtaed2xpHsD9ESMhqIYd0nLMwNLD69Npy4HI+N" crossorigin="anonymous">
        </head>
        <body>

                <div class="container">
                <div class="row justify-content-center">
                    <div class="card shadow-lg my-5">
                    <div class="card-body p-0">
                        <div class="row">
                            <div class="p-5">
                            <div class="text-center">
                                <h4 class="text-primary">GI-KACE RESET PASSWORD</h4>
                            </div>
                            <form class="user" action="http://localhost:8000/update?token={token}" method="POST" enctype="multipart/form-data">

                                <input type="hidden" name="token" value="{token}">
                
                                <div class="form-group">
                                    <label>PASSWORD</label>
                                <input type="password" name="password" id="password" class="form-control form-control-user" autocomplete="off" placeholder="Enter Password" required>
                                <span id="error_password" style="color: red;" ></span>                
                                </div>

                                <div class="form-group">
                                    <label>CONFIRM PASSWORD</label>
                                    <input type="password" id="conpassword" class="form-control form-control-user" autocomplete="true" placeholder="Confirm Password" required>  
                                    <span id="error_conpassword" style="color: red;"></span>
                                </div>

                    <button type="submit" class="btn btn-primary text-center  btn-user btn-block" onclick="return clickMe()">Reset</button>
                                <hr>
                            </form>
                            </div>
                        </div>
                        </div>
                    </div>
                </div>
            </div>

        </body>
        </html>

            """
    return html

















if __name__ == "__main__":
    port = int(8000)

    app_module = "main:app"
    uvicorn.run(app_module, host="0.0.0.0", port=port, reload=True)