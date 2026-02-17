from fastapi import FastAPI, Request, HTTPException, Depends, Form, Header
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import pandas as pd
import sqlite3
from datetime import datetime, timedelta
import uuid
from passlib.context import CryptContext

# 1️⃣ Crear la aplicación FastAPI
app = FastAPI()

# 2️⃣ Conectar frontend
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# 3️⃣ Configuración de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

# 4️⃣ Cargar Excel base
try:
    df = pd.read_excel("Inventario.xlsx")
    df.columns = df.columns.str.strip().str.lower()
except FileNotFoundError:
    df = pd.DataFrame(columns=["codigo", "descripcion", "stock"])

# 5️⃣ Modelo de producto
class Producto(BaseModel):
    codigo: str | None = None
    descripcion: str | None = None
    fecha_vencimiento: str

def estado_vencimiento(fecha_vencimiento: str) -> str:
    hoy = datetime.today().date()
    fecha = datetime.strptime(fecha_vencimiento, "%Y-%m-%d").date()
    dias = (fecha - hoy).days
    if dias < 0:
        return "Vencido"
    elif dias == 0:
        return "Se vence hoy"
    elif dias <= 7:
        return f"Crítico (<7 días)"
    return f"Correcto ({dias} días restantes)"

# 6️⃣ Tokens en memoria
tokens = {}

def crear_token(usuario_id: int) -> str:
    token = str(uuid.uuid4())
    tokens[token] = {
        "usuario_id": usuario_id,
        "expira": datetime.utcnow() + timedelta(minutes=30)
    }
    return token

def obtener_usuario(authorization: str = Header(...)):
    try:
        scheme, token = authorization.split()
    except ValueError:
        raise HTTPException(status_code=401, detail="Formato inválido")

    if scheme.lower() != "bearer" or token not in tokens:
        raise HTTPException(status_code=401, detail="No autorizado")

    datos = tokens[token]
    if datetime.utcnow() > datos["expira"]:
        del tokens[token]
        raise HTTPException(status_code=401, detail="Token expirado")

    return datos["usuario_id"]

# 7️⃣ Endpoints de usuarios
@app.post("/registro")
def registro(usuario: str = Form(...), contraseña: str = Form(...)):
    conn = sqlite3.connect("Inventario.db")
    c = conn.cursor()
    hashed = hash_password(contraseña)
    try:
        c.execute("INSERT INTO usuarios (usuario, contraseña) VALUES (?, ?)", (usuario, hashed))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    finally:
        conn.close()
    return {"mensaje": "Usuario registrado"}

@app.post("/login")
def login(usuario: str = Form(...), contraseña: str = Form(...)):
    conn = sqlite3.connect("Inventario.db")
    c = conn.cursor()
    c.execute("SELECT id, contraseña FROM usuarios WHERE usuario = ?", (usuario,))
    user = c.fetchone()
    conn.close()

    if user and verify_password(contraseña, user[1]):
        token = crear_token(user[0])
        return {"token": token}
    else:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

# 8️⃣ Endpoints de inventario
@app.post("/agregar_producto")
def agregar_producto(prod: Producto, usuario_id: int = Depends(obtener_usuario)):
    producto = df[df["codigo"].astype(str).str.strip().str.upper() == prod.codigo.strip().upper()]
    if producto.empty:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    datos = producto.to_dict(orient="records")[0]

    conn = sqlite3.connect("Inventario.db")
    c = conn.cursor()
    c.execute("""
        INSERT INTO items (usuario_id, codigo, descripcion, stock, fecha_vencimiento, estado)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        usuario_id,
        datos.get("codigo", ""),
        datos.get("descripcion", ""),
        datos.get("stock", ""),
        prod.fecha_vencimiento,
        estado_vencimiento(prod.fecha_vencimiento)
    ))
    conn.commit()
    conn.close()

    return {"mensaje": "Producto agregado"}

@app.get("/mis_productos")
def mis_productos(usuario_id: int = Depends(obtener_usuario)):
    conn = sqlite3.connect("Inventario.db")
    c = conn.cursor()
    c.execute("SELECT codigo, descripcion, stock, fecha_vencimiento, estado FROM items WHERE usuario_id = ?", (usuario_id,))
    productos = c.fetchall()
    conn.close()
    return {"productos": productos}

# 9️⃣ Panel de administrador
@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request, usuario_id: int = Depends(obtener_usuario)):
    if usuario_id != 1:  # Solo el master
        raise HTTPException(status_code=403, detail="Acceso denegado")

    conn = sqlite3.connect("Inventario.db")
    c = conn.cursor()
    c.execute("""
        SELECT t.token, u.usuario, t.ip, t.navegador, t.expira, t.activo
        FROM tokens t
        JOIN usuarios u ON t.usuario_id = u.id
    """)
    sesiones = c.fetchall()

    c.execute("SELECT * FROM alertas ORDER BY fecha DESC")
    alertas = c.fetchall()
    conn.close()

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "sesiones": sesiones,
        "alertas": alertas
    })

@app.post("/admin/cerrar_sesion")
def cerrar_sesion(token: str = Form(...), usuario_id: int = Depends(obtener_usuario)):
    if usuario_id != 1:
        raise HTTPException(status_code=403, detail="Acceso denegado")

    conn = sqlite3.connect("Inventario.db")
    c = conn.cursor()
    c.execute("UPDATE tokens SET activo = 0 WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=303)

# 🔟 Arranque del servidor
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)

