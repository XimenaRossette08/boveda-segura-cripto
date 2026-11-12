# main.py
import os
import jwt
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# --- 1. CONFIGURACIÓN DE LLAVES Y CRIPTOGRAFÍA ---
load_dotenv()
FERNET_KEY = os.getenv("SECRET_SYMMETRIC_KEY").encode()
cipher_suite = Fernet(FERNET_KEY)

with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

# --- 2. BASE DE DATOS SQLITE ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./boveda.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Nota(Base):
    __tablename__ = "notas"
    id = Column(Integer, primary_key=True, index=True)
    usuario = Column(String, index=True)
    nota_cifrada = Column(String)

Base.metadata.create_all(bind=engine)

# --- 3. APLICACIÓN FASTAPI ---
app = FastAPI(title="Bóveda Segura")

# ¡ESTA LÍNEA MAGICA HABILITA EL CANDADITO OFICIAL!
security = HTTPBearer() 

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verificar_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        # El candadito ya extrae el token limpio automáticamente
        token = credentials.credentials
        payload = jwt.decode(token, public_key, algorithms=["RS256"])
        return payload["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="Firma de token inválida")

class LoginRequest(BaseModel):
    usuario: str
class NotaCreate(BaseModel):
    texto_secreto: str

# --- 4. ENDPOINTS ---
@app.post("/login")
def login(req: LoginRequest):
    payload = {"sub": req.usuario}
    token = jwt.encode(payload, private_key, algorithm="RS256")
    return {"access_token": token, "token_type": "bearer"}

@app.post("/notas")
def crear_nota(nota: NotaCreate, db: Session = Depends(get_db), usuario: str = Depends(verificar_token)):
    texto_cifrado = cipher_suite.encrypt(nota.texto_secreto.encode('utf-8')).decode('utf-8')
    nueva_nota = Nota(usuario=usuario, nota_cifrada=texto_cifrado)
    db.add(nueva_nota)
    db.commit()
    return {"mensaje": "Nota guardada y cifrada de forma segura"}

@app.get("/notas")
def leer_notas(db: Session = Depends(get_db), usuario: str = Depends(verificar_token)):
    notas_db = db.query(Nota).filter(Nota.usuario == usuario).all()
    notas_descifradas = []
    for n in notas_db:
        texto_claro = cipher_suite.decrypt(n.nota_cifrada.encode('utf-8')).decode('utf-8')
        notas_descifradas.append({"id": n.id, "texto_secreto": texto_claro})
    return {"tus_notas": notas_descifradas}