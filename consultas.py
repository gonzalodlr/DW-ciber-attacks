import mysql.connector
import pandas as pd
from tabulate import tabulate

def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="gonzalo",
        database="ciberseguridad_db"
    )

def fetch_data(query, connection):
    cursor = connection.cursor()
    cursor.execute(query)
    data = cursor.fetchall()
    columns = [col[0] for col in cursor.description]
    cursor.close()
    return pd.DataFrame(data, columns=columns)

def display_results():
    conn = connect_db()
    
    queries = {
        "🔹 Tráfico más frecuente por protocolo": """
            SELECT p.protocolo AS Protocolo, COUNT(h.id_ataque) AS Total_Ataques
            FROM hechos_ataques h
            JOIN dim_protocolo p ON h.id_protocolo = p.id_protocolo
            GROUP BY p.protocolo
            ORDER BY Total_Ataques DESC
            LIMIT 10;
        """,
        
        "🔹 Direcciones IP de origen con más ataques": """
            SELECT o.ip_origen AS IP_Origen, COUNT(h.id_ataque) AS Total_Ataques
            FROM hechos_ataques h
            JOIN dim_origen o ON h.id_origen = o.id_origen
            GROUP BY o.ip_origen
            ORDER BY Total_Ataques DESC
            LIMIT 10;
        """,
        
        "🔹 Segmentos de red más atacados": """
            SELECT s.segmento AS Segmento, COUNT(h.id_ataque) AS Total_Ataques
            FROM hechos_ataques h
            JOIN dim_segmento s ON h.id_segmento = s.id_segmento
            GROUP BY s.segmento
            ORDER BY Total_Ataques DESC;
        """,
        
        "🔹 Ataques por nivel de severidad": """
            SELECT s.nivel_severidad AS Nivel_Severidad, COUNT(h.id_ataque) AS Total_Ataques
            FROM hechos_ataques h
            JOIN dim_severidad s ON h.id_severidad = s.id_severidad
            GROUP BY s.nivel_severidad
            ORDER BY Total_Ataques DESC;
        """,
        
        "🔹 Promedio de alertas generadas por ataque": """
            SELECT ROUND(AVG(h.numero_alertas), 2) AS Promedio_Alertas
            FROM hechos_ataques h;
        """
    }
    
    for title, query in queries.items():
        print(f"\n{title}")
        df = fetch_data(query, conn)
        print(tabulate(df, headers='keys', tablefmt='pretty'))
    
    conn.close()

if __name__ == "__main__":
    display_results()
