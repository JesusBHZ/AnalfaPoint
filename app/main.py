import mysql.connector
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from pydantic import BaseModel
from typing import Optional
from locale import currency
from turtle import title
from unicodedata import name
from fastapi import FastAPI
import sqlite3
from typing import List
from fastapi import HTTPException, status
from pydantic import BaseModel
from pydantic import EmailStr
from fastapi.responses import JSONResponse
import pymysql
import uvicorn
from dotenv import load_dotenv
import os



# uvicorn app.main:app --host 192.168.8.28 --port 8000

# MySQL Connection
HOST = "localhost"
USER = "root"
PASSWORD = ""
DATABASE = "analfa"
db = mysql.connector.connect(
    host=HOST,
    user=USER,
    password=PASSWORD,
    database=DATABASE
)

# FastAPI app
app = FastAPI()

description = """
 ---
 API REST para el uso exclusivo del sistema Analfa "El mejor lugar para aprender a leer"
 """
app = FastAPI(
    title="ANALFA API REST",
    description=description,
    version="0.0.1",
    terms_of_service="http/example.com/terms/",
    contact={
        "name": "Jesus BHZ",
        "url": "https://github.com/JesusBHZ",
        "email": "jesus1821bautista@gmail.com",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html"
    },)

load_dotenv()

# JWT Config
SECRET_KEY = os.getenv('SECRET_KEY')

# SECRET_KEY = "45rt67YUHJfghje4rdfcgvhuierdfgvbhjn5rtfgyhbjnm"
ALGORITHM = os.getenv('ALGORITHM')

# ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 config
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Password hash
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# User model


class UserInDB(BaseModel):
    username: str
    hashed_password: str

# Modelo de respuesta Mensaje


class Mensaje(BaseModel):
    mensaje: str

# Function to get user by username from MySQL database


def get_user(username: str):
    cursor = db.cursor()
    query = "SELECT UUID, password FROM docentes WHERE UUID =%s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    if user:
        return UserInDB(username=user[0], hashed_password=user[1])

# Function to verify password


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to authenticate user


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Function to create access token


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=35)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Route to get access token


@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=400, detail="Incorrect username or password"
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Route to test access token


@app.get("/",
         status_code=status.HTTP_202_ACCEPTED,
         summary="Endpoint principal",
         description="Regresa un mensaje de Bienvenida")
async def read_root(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials")

    return {"Hello": username}


# Route to get all records
@app.get("/users",
         status_code=status.HTTP_202_ACCEPTED,
         summary="Endpoint para iniciar con usuario y contraseña",
         description="Inicio de sesion")
async def get_records(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials")

    cursor = db.cursor()
    query = "SELECT * FROM docentes"
    cursor.execute(query)
    resultados = []
    # Obtener nombres de columnas
    columnas = [i[0] for i in cursor.description]
    for fila in cursor.fetchall():
        diccionario = dict(zip(columnas, fila))
        resultados.append(diccionario)
    # print(resultados)
    return resultados


@app.get("/escuelas/{UUID}", status_code=status.HTTP_202_ACCEPTED,
         summary="Lista de escuelas filtradas por CCT",
         description="Endpoint que regresa el array de solo una escuela"
         )
async def read_record_by_id(CCT: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials")

    record = get_escuela(CCT)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    return record


def get_escuela(CCT: str):
    try:
        conexion = pymysql.connect(host='localhost',
                                   user='root',
                                   password='',
                                   db='analfa')
        try:
            with conexion.cursor() as cursor:
                # En este caso no necesitamos limpiar ningún dato
                consulta = "SELECT * FROM escuelas where cct = %s;"
                cursor.execute(consulta, CCT)
                resultados = []
                # Obtener nombres de columnas
                columnas = [i[0] for i in cursor.description]
                for fila in cursor.fetchall():
                    diccionario = dict(zip(columnas, fila))
                    resultados.append(diccionario)
                if len(resultados) == 0:
                    return JSONResponse(status_code=404, content={"message": "El CCT de la escuela no existe"})
                else:
                    return resultados
        finally:
            conexion.close()
    except Exception as error:
        print(f"Error en get.contactos {error.args}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ERROR al consultar datos"
        )


@app.get("/alumnos/{UUID}", status_code=status.HTTP_202_ACCEPTED,
         summary="Lista de alumnos solo UNO",
         description="Endpoint que regresa el array de solo un alumno"
         )
async def read_record_by_id(UUID: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials")

    record = get_alumno(UUID)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    return record


def get_alumno(UUID: str):
    try:
        conexion = pymysql.connect(host='localhost',
                                   user='root',
                                   password='',
                                   db='analfa')
        try:
            with conexion.cursor() as cursor:
                # En este caso no necesitamos limpiar ningún dato
                consulta = "SELECT * FROM alumnos where UUID = %s;"
                cursor.execute(consulta, UUID)
                resultados = []
                # Obtener nombres de columnas
                columnas = [i[0] for i in cursor.description]
                for fila in cursor.fetchall():
                    diccionario = dict(zip(columnas, fila))
                    resultados.append(diccionario)
                if len(resultados) == 0:
                    return JSONResponse(status_code=404, content={"message": "El UUID de ese alumno no existe"})
                else:
                    return resultados
        finally:
            conexion.close()
    except Exception as error:
        print(f"Error en get.contactos {error.args}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ERROR al consultar datos"
        )


@app.get("/alumnosBygroupDocent", status_code=status.HTTP_202_ACCEPTED,
         summary="Regresa todos los alumnos pertencientes a un grupo, cct y docente especificos",
         description="Endpoint que regresa los alumnos pertenecientes a un grupo filtrado por docente y CCT"
         )
async def read_record_by_id(grupo: str, cct: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials")

    record = get_alumnosBygroupDocent(grupo, cct)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    return record


def get_alumnosBygroupDocent(grupo: str, cct: str):
    try:
        conexion = pymysql.connect(host='localhost',
                                   user='root',
                                   password='',
                                   db='analfa')
        try:
            with conexion.cursor() as cursor:
                # En este caso no necesitamos limpiar ningún dato
                consulta = "SELECT * FROM alumnos where id_grupo = %s and CCT = %s;"
                values = (str(grupo), str(cct))
                cursor.execute(consulta, values)
                resultados = []
                # Obtener nombres de columnas
                columnas = [i[0] for i in cursor.description]
                for fila in cursor.fetchall():
                    diccionario = dict(zip(columnas, fila))
                    resultados.append(diccionario)
                if len(resultados) == 0:
                    return JSONResponse(status_code=404, content={"message": "No hay grupos con ese docente o CCT"})
                else:
                    return resultados
        finally:
            conexion.close()
    except Exception as error:
        print(f"Error en get.contactos {error.args}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ERROR al consultar datos"
        )


@app.get("/groupsBygroupDocent",
         status_code=status.HTTP_202_ACCEPTED,
         summary="Regresa todos los grupos pertencientes a un cct y docente especificos",
         description="Endpoint que regresa los grupos pertenecientes a un docente y CCT"
         )
async def read_record_by_id(docente: str, cct: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials")

    record = get_groupsBygroupDocent(docente, cct)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    return record


def get_groupsBygroupDocent(docente: str, cct: str):
    try:
        conexion = pymysql.connect(host='localhost',
                                   user='root',
                                   password='',
                                   db='analfa')
        try:
            with conexion.cursor() as cursor:
                # En este caso no necesitamos limpiar ningún dato
                consulta = "SELECT * FROM grupos where UUID_docente = %s and cct = %s;"
                values = (str(docente), str(cct))
                cursor.execute(consulta, values)
                resultados = []
                # Obtener nombres de columnas
                columnas = [i[0] for i in cursor.description]
                for fila in cursor.fetchall():
                    diccionario = dict(zip(columnas, fila))
                    resultados.append(diccionario)
                if len(resultados) == 0:
                    return JSONResponse(status_code=404, content={"message": "No hay grupos con ese docente o CCT"})
                else:
                    return resultados
        finally:
            conexion.close()
    except Exception as error:
        print(f"Error en get.contactos {error.args}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ERROR al consultar datos"
        )


@app.get("/docente/{UUID}",
         status_code=status.HTTP_202_ACCEPTED,
         summary="Lista de docentes solo UNO",
         description="Endpoint que regresa el array de solo un docente"
         )
async def get_docente(UUID: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials")

    record = get_docentebyUUID(UUID)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    return record


def get_docentebyUUID(UUID: str):
    try:
        conexion = pymysql.connect(host='localhost',
                                   user='root',
                                   password='',
                                   db='analfa')
        try:
            with conexion.cursor() as cursor:
                # En este caso no necesitamos limpiar ningún dato
                consulta = "SELECT * FROM docentes where UUID = %s;"
                cursor.execute(consulta, UUID)
                resultados = []
                # Obtener nombres de columnas
                columnas = [i[0] for i in cursor.description]
                for fila in cursor.fetchall():
                    diccionario = dict(zip(columnas, fila))
                    resultados.append(diccionario)
                if len(resultados) == 0:
                    return JSONResponse(status_code=404, content={"message": "El UUID de ese docente no existe"})
                else:
                    return resultados
        finally:
            conexion.close()
    except Exception as error:
        print(f"Error en get.contactos {error.args}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ERROR al consultar datos"
        )
