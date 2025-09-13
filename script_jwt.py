# o si usas VS Code
code script_jwt.py

#!/usr/bin/env python3
"""
script_jwt.py
Ejemplo completo:
 - Simula login (usuario/clave)
 - Crea JWT con payload pedido
 - Valida token con clave correcta
 - Intenta validar con clave incorrecta
 - Espera a que caduque y valida de nuevo (muestra expiración)
"""

import time
import jwt
from jwt import ExpiredSignatureError, InvalidSignatureError, InvalidTokenError
from datetime import datetime, timedelta

# Datos 
PAYLOAD_BASE = {
    "carnet": "1990-21-8618",
    "nombre": "Kevin Adolfo Tepaz Buc",
    "curso": "seguridad y auditoria de sistemas",
    "seccion": "B"
}

# Claves
SECRET = "Password"    
WRONG_SECRET = "clave_incorrecta"           

ALGORITHM = "HS256"

def crear_token(payload_extra=None, lifetime_seconds=5):
    """Crea y retorna un JWT con un exp corto (por default 5s)."""
    payload = PAYLOAD_BASE.copy()
    if payload_extra:
        payload.update(payload_extra)
    now = datetime.utcnow()
    payload.update({
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=lifetime_seconds)).timestamp())
    })
    token = jwt.encode(payload, SECRET, algorithm=ALGORITHM)
    # PyJWT en versiones recientes retorna str; en versiones antiguas bytes
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def validar_token(token, clave):
    """Intenta decodificar el token con la clave dada y devuelve la info o el error."""
    try:
        decoded = jwt.decode(token, clave, algorithms=[ALGORITHM])
        return ("OK", decoded)
    except ExpiredSignatureError as e:
        return ("EXPIRED", str(e))
    except InvalidSignatureError as e:
        return ("INVALID_SIGNATURE", str(e))
    except InvalidTokenError as e:
        return ("INVALID_TOKEN", str(e))
    except Exception as e:
        return ("ERROR", str(e))

def simular_login(username, password):
    """Simulación simple de login — si coincide, devuelve token."""
    # Usuario/clave hardcodeados para demo. Cambia según necesites.
    if username == "kevin" and password == "password123":
        print("[login] Credenciales correctas. Generando token...")
        token = crear_token(lifetime_seconds=5)  # 5 segundos para demostrar expiración
        return token
    else:
        raise ValueError("Credenciales inválidas")

def main():
    print("=== Simulación de inicio de sesión y JWT ===")
    # 1) Simular login
    try:
        token = simular_login("kevin", "password123")
    except ValueError as e:
        print("Login fallido:", e)
        return

    print("\nToken generado:\n", token)

    # 2) Validar inmediatamente con la clave correcta
    estado, info = validar_token(token, SECRET)
    print("\nValidación inmediata con clave CORRECTA:")
    print("Estado:", estado)
    print("Contenido:", info)

    # 3) Validar con clave incorrecta
    estado2, info2 = validar_token(token, WRONG_SECRET)
    print("\nValidación inmediata con clave INCORRECTA:")
    print("Estado:", estado2)
    print("Mensaje:", info2)

    # 4) Esperar a que caduque (un poco más que lifetime)
    espera = 7
    print(f"\nEsperando {espera} segundos para que expire el token...")
    time.sleep(espera)

    # 5) Intentar validar de nuevo con la clave correcta (debe salir expirado)
    estado3, info3 = validar_token(token, SECRET)
    print("\nValidación después de expiración (con clave CORRECTA):")
    print("Estado:", estado3)
    print("Mensaje/Contenido:", info3)

    print("\n--- Resumen del payload pedido ---")
    print("Número de carnet:", PAYLOAD_BASE["carnet"])
    print("Nombre completo:", PAYLOAD_BASE["nombre"])
    print("Curso:", PAYLOAD_BASE["curso"])
    print("Sección:", PAYLOAD_BASE["seccion"])

if __name__ == "__main__":
    main()
