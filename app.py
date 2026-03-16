from fastapi import FastAPI, File, Request, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional
import pandas as pd
import io
import zipfile
from datetime import datetime

# 1️⃣ Crear la aplicación FastAPI
app = FastAPI()

# 2️⃣ Conectar frontend
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# 3️⃣ Cargar catálogo Excel
try:
    df_catalogo = pd.read_excel("Inventario.xlsx")
    df_catalogo.columns = df_catalogo.columns.str.strip().str.lower()
except FileNotFoundError:
    df_catalogo = pd.DataFrame(columns=["codigo", "descripcion", "stock"])

# 4️⃣ Lista en memoria de productos de la sesión
lista_productos: list = []

# 5️⃣ Modelo de producto
class Producto(BaseModel):
    codigo: Optional[str] = None
    descripcion: Optional[str] = None
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

def lista_to_response(lista: list) -> list:
    return [
        {
            "Codigo": str(p["codigo"]),
            "Descripcion": str(p["descripcion"]),
            "Stock": str(p.get("stock", "")),
            "FechaVencimiento": p["fecha_vencimiento"],
            "Estado": p["estado"],
        }
        for p in lista
    ]

def _cargar_excel_bytes(contenido: bytes) -> Optional[pd.DataFrame]:
    """Lee un archivo Excel desde bytes y normaliza las columnas."""
    try:
        df = pd.read_excel(io.BytesIO(contenido))
        df.columns = df.columns.str.strip().str.lower()
        return df
    except Exception:
        return None

# 6️⃣ Subir carpeta completa (archivos individuales o ZIP)
@app.post("/upload_carpeta")
async def upload_carpeta(archivos: List[UploadFile] = File(...)):
    """
    Acepta uno o varios archivos:
    - Si se sube un .zip, se extraen todos los .xlsx/.xls que contenga.
    - Si se suben directamente archivos Excel, se procesan uno a uno.
    Los datos reemplazan el catálogo en memoria.
    """
    global df_catalogo

    dfs = []

    for archivo in archivos:
        nombre = (archivo.filename or "").lower()
        contenido = await archivo.read()

        if nombre.endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(contenido)) as zf:
                    for entry in zf.namelist():
                        entry_lower = entry.lower()
                        if entry_lower.endswith(".xlsx") or entry_lower.endswith(".xls"):
                            df_nuevo = _cargar_excel_bytes(zf.read(entry))
                            if df_nuevo is not None:
                                dfs.append(df_nuevo)
            except zipfile.BadZipFile:
                raise HTTPException(status_code=400, detail=f"El archivo '{archivo.filename}' no es un ZIP válido")

        elif nombre.endswith(".xlsx") or nombre.endswith(".xls"):
            df_nuevo = _cargar_excel_bytes(contenido)
            if df_nuevo is not None:
                dfs.append(df_nuevo)

    if not dfs:
        raise HTTPException(
            status_code=400,
            detail="No se encontraron archivos Excel (.xlsx/.xls) en los archivos subidos",
        )

    df_catalogo = pd.concat(dfs, ignore_index=True).drop_duplicates()
    return {
        "mensaje": f"Catálogo actualizado con {len(df_catalogo)} productos",
        "total_productos": len(df_catalogo),
    }


@app.get("/api/articulos")
def get_articulos():
    if "descripcion" in df_catalogo.columns:
        return df_catalogo["descripcion"].dropna().astype(str).tolist()
    return []

@app.get("/nombres")
def get_nombres():
    if "descripcion" in df_catalogo.columns:
        return {"nombres": df_catalogo["descripcion"].dropna().astype(str).tolist()}
    return {"nombres": []}

# 7️⃣ Lista de productos en sesión
@app.get("/lista")
def get_lista():
    return {"lista": lista_to_response(lista_productos)}

@app.post("/agregar_producto")
def agregar_producto(prod: Producto):
    codigo = (prod.codigo or "").strip()
    descripcion = (prod.descripcion or "").strip()

    if codigo and descripcion:
        raise HTTPException(status_code=400, detail="Ingresa SOLO código O nombre, no ambos")
    if not codigo and not descripcion:
        raise HTTPException(status_code=400, detail="Ingresa código o nombre")
    if not prod.fecha_vencimiento:
        raise HTTPException(status_code=400, detail="Ingresa fecha de vencimiento")

    if codigo:
        match = df_catalogo[
            df_catalogo["codigo"].astype(str).str.strip().str.upper() == codigo.upper()
        ]
    else:
        match = df_catalogo[
            df_catalogo["descripcion"].astype(str).str.strip().str.lower() == descripcion.lower()
        ]

    if match.empty:
        raise HTTPException(status_code=404, detail="Producto no encontrado en el catálogo")

    datos = match.to_dict(orient="records")[0]
    nuevo = {
        "codigo": str(datos.get("codigo", "")),
        "descripcion": str(datos.get("descripcion", "")),
        "stock": str(datos.get("stock", "")),
        "fecha_vencimiento": prod.fecha_vencimiento,
        "estado": estado_vencimiento(prod.fecha_vencimiento),
    }
    lista_productos.append(nuevo)
    return {"lista": lista_to_response(lista_productos), "mensaje": "Producto agregado"}

@app.delete("/borrar_producto/{codigo}")
def borrar_producto(codigo: str):
    for i, p in enumerate(lista_productos):
        if str(p["codigo"]).strip().upper() == codigo.strip().upper():
            lista_productos.pop(i)
            return {"lista": lista_to_response(lista_productos), "mensaje": "Producto eliminado"}
    raise HTTPException(status_code=404, detail="Producto no encontrado en la lista")

@app.put("/modificar_producto/{codigo}")
def modificar_producto(codigo: str, nueva_fecha: str = Query(...)):
    for p in lista_productos:
        if str(p["codigo"]).strip().upper() == codigo.strip().upper():
            p["fecha_vencimiento"] = nueva_fecha
            p["estado"] = estado_vencimiento(nueva_fecha)
            return {"lista": lista_to_response(lista_productos), "mensaje": "Producto modificado"}
    raise HTTPException(status_code=404, detail="Producto no encontrado en la lista")

@app.post("/guardar_lista")
def guardar_lista():
    if not lista_productos:
        raise HTTPException(status_code=400, detail="La lista está vacía")

    rows = [
        {
            "Codigo": p["codigo"],
            "Descripcion": p["descripcion"],
            "Stock": p.get("stock", ""),
            "Fecha Vencimiento": p["fecha_vencimiento"],
            "Estado": p["estado"],
        }
        for p in lista_productos
    ]
    df_export = pd.DataFrame(rows)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df_export.to_excel(writer, index=False)
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=lista_final.xlsx"},
    )

# 8️⃣ Arranque del servidor
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)

