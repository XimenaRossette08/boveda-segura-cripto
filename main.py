# main.py
import os
import hashlib
import secrets
import jwt
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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

# Funciones para proteger contraseñas con Hash PBKDF2-HMAC-SHA256 + Salt
def hashear_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${hash_bytes.hex()}"

def verificar_password(password_plano: str, password_hash_bd: str) -> bool:
    try:
        salt, hash_original = password_hash_bd.split("$")
        hash_nuevo = hashlib.pbkdf2_hmac('sha256', password_plano.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
        return secrets.compare_digest(hash_nuevo, hash_original)
    except Exception:
        return False

# --- 2. BASE DE DATOS SQLITE ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./boveda.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    usuario = Column(String, unique=True, index=True)
    password_hash = Column(String)

class Nota(Base):
    __tablename__ = "notas"
    id = Column(Integer, primary_key=True, index=True)
    usuario = Column(String, index=True)
    nota_cifrada = Column(String)

Base.metadata.create_all(bind=engine)

# --- 3. APLICACIÓN FASTAPI ---
app = FastAPI(title="Bóveda Segura")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verificar_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, public_key, algorithms=["RS256"])
        return payload["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="Firma de token inválida")

class AuthRequest(BaseModel):
    usuario: str
    password: str

class NotaCreate(BaseModel):
    texto_secreto: str

# --- 4. ENDPOINTS ---
@app.get("/", include_in_schema=False)
def servir_interfaz():
    return FileResponse("index.html")

@app.post("/registro")
def registrar_usuario(req: AuthRequest, db: Session = Depends(get_db)):
    existe = db.query(Usuario).filter(Usuario.usuario == req.usuario).first()
    if existe:
        raise HTTPException(status_code=400, detail="Este nombre de usuario ya está registrado")
    
    nuevo_usuario = Usuario(
        usuario=req.usuario,
        password_hash=hashear_password(req.password)
    )
    db.add(nuevo_usuario)
    db.commit()
    return {"mensaje": f"Usuario '{req.usuario}' registrado con contraseña protegida (PBKDF2-SHA256)"}

@app.post("/login")
def login(req: AuthRequest, db: Session = Depends(get_db)):
    user_db = db.query(Usuario).filter(Usuario.usuario == req.usuario).first()
    if not user_db or not verificar_password(req.password, user_db.password_hash):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas: Acceso denegado para firmar token")
    
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
        notas_descifradas.append({
            "id": n.id,
            "como_se_guarda_en_bd_cifrado": n.nota_cifrada, 
            "como_lo_ve_el_usuario_descifrado": texto_claro
        })
    return {"tus_notas": notas_descifradas}