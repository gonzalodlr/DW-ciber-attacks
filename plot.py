import mysql.connector
import pandas as pd
import matplotlib.pyplot as plt

# Conectar a MySQL
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="gonzalo",
    database="ciberseguridad_db"
)

# Cargar datos desde MySQL
query = """
SELECT s.nivel_severidad, COUNT(*) as total_ataques
FROM hechos_ataques h
JOIN dim_severidad s ON h.id_severidad = s.id_severidad
GROUP BY s.nivel_severidad
ORDER BY total_ataques DESC;
"""
df = pd.read_sql(query, conn)

# Graficar
plt.figure(figsize=(8,5))
plt.bar(df["nivel_severidad"], df["total_ataques"], color=["green", "yellow", "red"])
plt.xlabel("Nivel de Severidad")
plt.ylabel("Número de Ataques")
plt.title("Distribución de Ataques por Severidad")
plt.show()
