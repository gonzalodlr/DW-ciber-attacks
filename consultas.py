import mysql.connector
import pandas as pd
import matplotlib.pyplot as plt
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

def plot_data(df, title, xlabel, ylabel, chart_type="bar"):
    if df.empty or df.shape[1] < 2:
        print(f"No hay suficientes datos para graficar: {title}")
        plt.figure(figsize=(4, 2))
        plt.table(cellText=df.values, colLabels=df.columns, loc='center', cellLoc='center')
        plt.axis('off')
        plt.title(title)
        plt.show()
        return
    
    plt.figure(figsize=(8, 5))
    
    if chart_type == "bar":
        plt.bar(df.iloc[:, 0], df.iloc[:, 1], color="skyblue")
    elif chart_type == "pie":
        plt.pie(df.iloc[:, 1], labels=df.iloc[:, 0], autopct='%1.1f%%', startangle=140)
    elif chart_type == "line":
        plt.plot(df.iloc[:, 0], df.iloc[:, 1], marker='o', linestyle='-')
    
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=45)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.show()

def display_results():
    conn = connect_db()
    
    queries = {
        "Tráfico más frecuente por protocolo": ("""
            SELECT p.protocolo AS Protocolo, COUNT(h.id_ataque) AS Total_Ataques
            FROM hechos_ataques h
            JOIN dim_protocolo p ON h.id_protocolo = p.id_protocolo
            GROUP BY p.protocolo
            ORDER BY Total_Ataques DESC
            LIMIT 10;
        """, "Protocolo", "Número de ataques", "bar"),
        
        "Direcciones IP de origen con más ataques": ("""
            SELECT o.ip_origen AS IP_Origen, COUNT(h.id_ataque) AS Total_Ataques
            FROM hechos_ataques h
            JOIN dim_origen o ON h.id_origen = o.id_origen
            GROUP BY o.ip_origen
            ORDER BY Total_Ataques DESC
            LIMIT 10;
        """, "Direcciones IP", "Número de ataques", "bar"),
        
        "Segmentos de red más atacados": ("""
            SELECT s.segmento AS Segmento, COUNT(h.id_ataque) AS Total_Ataques
            FROM hechos_ataques h
            JOIN dim_segmento s ON h.id_segmento = s.id_segmento
            GROUP BY s.segmento
            ORDER BY Total_Ataques DESC;
        """, "Segmento de red", "Número de ataques", "bar"),
        
        "Ataques por nivel de severidad": ("""
            SELECT s.nivel_severidad AS Nivel_Severidad, COUNT(h.id_ataque) AS Total_Ataques
            FROM hechos_ataques h
            JOIN dim_severidad s ON h.id_severidad = s.id_severidad
            GROUP BY s.nivel_severidad
            ORDER BY Total_Ataques DESC;
        """, "Nivel de Severidad", "Número de ataques", "pie"),
        
        "Promedio de alertas generadas por ataque": ("""
            SELECT ROUND(AVG(h.numero_alertas), 2) AS Promedio_Alertas
            FROM hechos_ataques h;
        """, "", "Promedio de alertas", "table"),

        "Ubicaciones geográficas con más ataques": ("""
            SELECT g.ubicacion AS Ubicacion, COUNT(h.id_ataque) AS Total_Ataques
            FROM hechos_ataques h
            JOIN dim_geo g ON h.id_geo = g.id_geo
            GROUP BY g.ubicacion
            ORDER BY Total_Ataques DESC
            LIMIT 10;
        """, "Ubicación", "Número de ataques", "bar")
    }
    
    for title, (query, xlabel, ylabel, chart_type) in queries.items():
        print(f"\n{title}")
        df = fetch_data(query, conn)
        print(tabulate(df, headers='keys', tablefmt='pretty'))
        
        if not df.empty:
            plot_data(df, title, xlabel, ylabel, chart_type)
    
    conn.close()

if __name__ == "__main__":
    display_results()
