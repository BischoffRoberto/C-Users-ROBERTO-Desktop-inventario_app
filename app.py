from fastapi import FastAPI, Request, HTTPException, Depends, Form, Header, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import pandas as pd
import sqlite3
import io
from datetime import datetime, timedelta
import uuid
from passlib.context import CryptContext

# 1️⃣ Crear la aplicación FastAPI
app = FastAPI()

# 2️⃣ Conectar frontend
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# 3️⃣ Configuración de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

# 4️⃣ Cargar Excel base
def cargar_excel():
    try:
        df = pd.read_excel("Inventario.xlsx")
        df.columns = df.columns.str.strip().str.lower()
        return df
    except FileNotFoundError:
        return pd.DataFrame(columns=["codigo", "descripcion", "stock"])

df = cargar_excel()

# 5️⃣ Lista temporal en memoria (productos agregados en la sesión actual)
lista_temporal = []

# 6️⃣ Modelo de producto
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
        return "Crítico (<7 días)"
    return f"Correcto ({dias} días restantes)"

# 7️⃣ Tokens en memoria
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

# 8️⃣ Inicializar base de datos
def init_db():
    conn = sqlite3.connect("Inventario.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            contraseña TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            codigo TEXT,
            descripcion TEXT,
            stock TEXT,
            fecha_vencimiento TEXT,
            estado TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            usuario_id INTEGER,
            ip TEXT,
            navegador TEXT,
            expira TEXT,
            activo INTEGER DEFAULT 1
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS alertas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            mensaje TEXT,
            fecha TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# 9️⃣ Endpoints públicos para el frontend

@app.get("/api/articulos")
def get_articulos():
    """Returns list of article names from the Excel file."""
    nombres = []
    if "descripcion" in df.columns:
        nombres = df["descripcion"].dropna().astype(str).str.strip().unique().tolist()
    return nombres

@app.get("/nombres")
def get_nombres():
    """Returns article names (fallback endpoint)."""
    nombres = []
    if "descripcion" in df.columns:
        nombres = df["descripcion"].dropna().astype(str).str.strip().unique().tolist()
    return {"nombres": nombres}

@app.get("/lista")
def get_lista():
    """Returns the current temporary product list."""
    return {"lista": lista_temporal}

@app.post("/agregar_producto")
def agregar_producto(prod: Producto):
    """Adds a product to the temporary list by code or description."""
    global df

    if prod.codigo and prod.codigo.strip():
        mask = df["codigo"].astype(str).str.strip().str.upper() == prod.codigo.strip().upper()
        producto = df[mask]
    elif prod.descripcion and prod.descripcion.strip():
        mask = df["descripcion"].astype(str).str.strip().str.upper() == prod.descripcion.strip().upper()
        producto = df[mask]
    else:
        raise HTTPException(status_code=400, detail="Ingresa código o descripción")

    if producto.empty:
        raise HTTPException(status_code=404, detail="Producto no encontrado en el inventario")

    datos = producto.to_dict(orient="records")[0]
    estado = estado_vencimiento(prod.fecha_vencimiento)

    item = {
        "Codigo": str(datos.get("codigo", "")),
        "Descripcion": str(datos.get("descripcion", "")),
        "Stock": str(datos.get("stock", "")),
        "FechaVencimiento": prod.fecha_vencimiento,
        "Estado": estado,
    }
    lista_temporal.append(item)

    return {"mensaje": "Producto agregado", "lista": lista_temporal}

@app.post("/guardar_lista")
def guardar_lista():
    """Saves the temporary list to an Excel file and streams it for download."""
    if not lista_temporal:
        raise HTTPException(status_code=400, detail="La lista está vacía")

    df_lista = pd.DataFrame(lista_temporal)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df_lista.to_excel(writer, index=False, sheet_name="Lista")
    output.seek(0)

    headers = {
        "Content-Disposition": "attachment; filename=lista_final.xlsx"
    }
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers,
    )

@app.delete("/borrar_producto/{codigo}")
def borrar_producto(codigo: str):
    """Removes the first matching product from the temporary list by code."""
    idx = next(
        (i for i, p in enumerate(lista_temporal) if str(p.get("Codigo", "")) == str(codigo)),
        None,
    )
    if idx is None:
        raise HTTPException(status_code=404, detail="Producto no encontrado en la lista")
    lista_temporal.pop(idx)
    return {"mensaje": "Producto eliminado", "lista": lista_temporal}

@app.put("/modificar_producto/{codigo}")
def modificar_producto(codigo: str, nueva_fecha: str):
    """Modifies the expiration date of the first matching product in the temporary list."""
    for p in lista_temporal:
        if str(p.get("Codigo", "")) == str(codigo):
            p["FechaVencimiento"] = nueva_fecha
            p["Estado"] = estado_vencimiento(nueva_fecha)
            return {"mensaje": "Producto modificado", "lista": lista_temporal}
    raise HTTPException(status_code=404, detail="Producto no encontrado en la lista")

MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

@app.post("/subir_inventario")
async def subir_inventario(archivo: UploadFile = File(...)):
    """Uploads a new Excel inventory file to replace the current one."""
    global df
    filename = archivo.filename or ""
    if not (filename.endswith(".xlsx") or filename.endswith(".xls")):
        raise HTTPException(status_code=400, detail="El archivo debe ser Excel (.xlsx o .xls)")

    contenido = await archivo.read(MAX_UPLOAD_SIZE + 1)
    if len(contenido) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="El archivo es demasiado grande (máximo 10 MB)")

    try:
        df_nuevo = pd.read_excel(io.BytesIO(contenido))
        df_nuevo.columns = df_nuevo.columns.str.strip().str.lower()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al leer el archivo Excel: {str(e)}")

    with open("Inventario.xlsx", "wb") as f:
        f.write(contenido)
    df = df_nuevo

    return {"mensaje": f"Inventario actualizado correctamente con {len(df_nuevo)} productos"}

# 🔟 Endpoints de usuarios
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

@app.get("/mis_productos")
def mis_productos(usuario_id: int = Depends(obtener_usuario)):
    conn = sqlite3.connect("Inventario.db")
    c = conn.cursor()
    c.execute(
        "SELECT codigo, descripcion, stock, fecha_vencimiento, estado FROM items WHERE usuario_id = ?",
        (usuario_id,),
    )
    productos = c.fetchall()
    conn.close()
    return {"productos": productos}

# 1️⃣1️⃣ Panel de administrador
@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request, usuario_id: int = Depends(obtener_usuario)):
    if usuario_id != 1:
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

    return templates.TemplateResponse("adminin.html", {
        "request": request,
        "sesiones": sesiones,
        "alertas": alertas,
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

# 1️⃣2️⃣ Arranque del servidor
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)

