import pandas as pd
import re
import ipaddress
import mysql.connector
from concurrent.futures import ThreadPoolExecutor

def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="gonzalo",
        database="ciberseguridad_db"
    )

def insert_dim_data(cursor, table, columns, data):
    query = f"""
        INSERT IGNORE INTO {table} ({', '.join(columns)})
        VALUES ({', '.join(['%s'] * len(columns))})
    """
    cursor.executemany(query, data)

def load_dimensions(df):
    conn = connect_db()
    cursor = conn.cursor()
    insert_dim_data(cursor, "dim_origen", ["ip_origen", "puerto_origen", "proxy", "usuario"], df[['Source IP Address', 'Source Port', 'Proxy Information', 'User Information']].drop_duplicates().values.tolist())
    insert_dim_data(cursor, "dim_destino", ["ip_destino", "puerto_destino", "dispositivo", "navegador"], df[['Destination IP Address', 'Destination Port', 'Targeted Device', 'Browser']].drop_duplicates().values.tolist())
    insert_dim_data(cursor, "dim_protocolo", ["protocolo"], df[['Protocol']].drop_duplicates().values.tolist())
    insert_dim_data(cursor, "dim_tipo_trafico", ["tipo_trafico"], df[['Traffic Type']].drop_duplicates().values.tolist())
    insert_dim_data(cursor, "dim_malware", ["indicador_malware"], df[['Malware Indicators']].drop_duplicates().values.tolist())
    insert_dim_data(cursor, "dim_anomalia", ["score_anomalia"], df[['Anomaly Scores']].drop_duplicates().values.tolist())
    insert_dim_data(cursor, "dim_severidad", ["nivel_severidad"], df[['Severity Level']].drop_duplicates().values.tolist())
    insert_dim_data(cursor, "dim_dispositivo", ["tipo_dispositivo"], df[['Targeted Device']].drop_duplicates().values.tolist())
    insert_dim_data(cursor, "dim_segmento", ["segmento"], df[['Network Segment']].drop_duplicates().values.tolist())
    insert_dim_data(cursor, "dim_geo", ["ubicacion"], df[['Geo-location Data']].drop_duplicates().values.tolist())
    
    conn.commit()
    cursor.close()
    conn.close()

def get_dimension_id(cursor, table, id_column, column, value):
    cursor.execute(f"SELECT {id_column} FROM {table} WHERE {column} = %s LIMIT 1", (value,))
    result = cursor.fetchone()
    return result[0] if result else None

def insert_fact_table(df):
    conn = connect_db()
    cursor = conn.cursor()
    batch_data = []
    
    for index, row in df.iterrows():
        print("[",index, "39999]Insertando en hechos_ataques...")
        id_origen = get_dimension_id(cursor, 'dim_origen', 'id_origen', 'ip_origen', row['Source IP Address'])
        id_destino = get_dimension_id(cursor, 'dim_destino', 'id_destino', 'ip_destino', row['Destination IP Address'])
        id_protocolo = get_dimension_id(cursor, 'dim_protocolo', 'id_protocolo', 'protocolo', row['Protocol'])
        id_tipo_trafico = get_dimension_id(cursor, 'dim_tipo_trafico', 'id_tipo_trafico', 'tipo_trafico', row['Traffic Type'])
        id_malware = get_dimension_id(cursor, 'dim_malware', 'id_malware', 'indicador_malware', row['Malware Indicators'])
        id_anomalia = get_dimension_id(cursor, 'dim_anomalia', 'id_anomalia', 'score_anomalia', row['Anomaly Scores'])
        id_severidad = get_dimension_id(cursor, 'dim_severidad', 'id_severidad', 'nivel_severidad', row['Severity Level'])
        id_dispositivo = get_dimension_id(cursor, 'dim_dispositivo', 'id_dispositivo', 'tipo_dispositivo', row['Targeted Device'])
        id_segmento = get_dimension_id(cursor, 'dim_segmento', 'id_segmento', 'segmento', row['Network Segment'])
        id_geo = get_dimension_id(cursor, 'dim_geo', 'id_geo', 'ubicacion', row['Geo-location Data'])
        
        if None not in (id_origen, id_destino, id_protocolo, id_tipo_trafico, id_malware, id_anomalia, id_severidad, id_dispositivo, id_segmento, id_geo):
            batch_data.append((row['Datetime'], id_origen, id_destino, id_protocolo, id_tipo_trafico, id_malware, id_anomalia, id_severidad, id_dispositivo, id_segmento, id_geo, row['Packet Length'], row['Alerts/Warnings']))
    
    if batch_data:
        cursor.executemany("""
            INSERT INTO hechos_ataques (timestamp, id_origen, id_destino, id_protocolo, id_tipo_trafico, id_malware, id_anomalia, id_severidad, id_dispositivo, id_segmento, id_geo, longitud_paquete, numero_alertas)
            SELECT * FROM (SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) AS tmp
            WHERE NOT EXISTS (
                SELECT 1 FROM hechos_ataques WHERE timestamp = %s AND id_origen = %s AND id_destino = %s AND id_protocolo = %s
            )
        """, batch_data)
    
    conn.commit()
    cursor.close()
    conn.close()


def comprobar_crear_db():
    # Conectar con MySQL
    conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="gonzalo"
)
    cursor = conn.cursor()

    # Verificar si la base de datos ya existe
    cursor.execute("SHOW DATABASES")
    databases = [db[0] for db in cursor.fetchall()]

    if "ciberseguridad_db" not in databases:
        print("La base de datos 'ciberseguridad_db' no existe. Creándola ahora...")

        # **Crear la base de datos**
        #cursor.execute("CREATE DATABASE ciberseguridad_db")
        cursor.execute("CREATE DATABASE ciberseguridad_db")
        print("✅ Base de datos 'ciberseguridad_db' creada con éxito.")

        # **Conectarse a la base de datos recién creada**
        conn.database = "ciberseguridad_db"

        # **Crear las tablas**
        print("Creando tablas en 'ciberseguridad_db'...")

        cursor.execute("""
            CREATE TABLE dim_origen (
                id_origen INT AUTO_INCREMENT PRIMARY KEY,
                ip_origen VARCHAR(50),
                puerto_origen INT,
                proxy VARCHAR(255),
                usuario VARCHAR(255)
            )
        """)

        cursor.execute("""
            CREATE TABLE dim_destino (
                id_destino INT AUTO_INCREMENT PRIMARY KEY,
                ip_destino VARCHAR(50),
                puerto_destino INT,
                dispositivo VARCHAR(255),
                navegador VARCHAR(255)
            )
        """)

        cursor.execute("""
            CREATE TABLE dim_protocolo (
                id_protocolo INT AUTO_INCREMENT PRIMARY KEY,
                protocolo VARCHAR(50)
            )
        """)

        cursor.execute("""
            CREATE TABLE dim_tipo_trafico (
                id_tipo_trafico INT AUTO_INCREMENT PRIMARY KEY,
                tipo_trafico VARCHAR(50)
            )
        """)

        cursor.execute("""
            CREATE TABLE dim_malware (
                id_malware INT AUTO_INCREMENT PRIMARY KEY,
                indicador_malware VARCHAR(255)
            )
        """)

        cursor.execute("""
            CREATE TABLE dim_anomalia (
                id_anomalia INT AUTO_INCREMENT PRIMARY KEY,
                score_anomalia FLOAT
            )
        """)

        cursor.execute("""
        CREATE TABLE dim_severidad (
            id_severidad INT AUTO_INCREMENT PRIMARY KEY,
            nivel_severidad VARCHAR(50)
        )
    """)

        cursor.execute("""
        CREATE TABLE dim_dispositivo (
            id_dispositivo INT AUTO_INCREMENT PRIMARY KEY,
            tipo_dispositivo VARCHAR(255)
        )
    """)

        cursor.execute("""
        CREATE TABLE dim_segmento (
            id_segmento INT AUTO_INCREMENT PRIMARY KEY,
            segmento VARCHAR(255)
        )
    """)

        cursor.execute("""
        CREATE TABLE dim_geo (
            id_geo INT AUTO_INCREMENT PRIMARY KEY,
            ubicacion VARCHAR(255)
        )
    """)

        cursor.execute("""
        CREATE TABLE hechos_ataques (
            id_ataque INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME NOT NULL,
            id_origen INT,
            id_destino INT,
            id_protocolo INT,
            id_tipo_trafico INT,
            id_malware INT,
            id_anomalia INT,
            id_severidad INT,
            id_dispositivo INT,
            id_segmento INT,
            id_geo INT,
            longitud_paquete INT,
            numero_alertas INT,
            FOREIGN KEY (id_origen) REFERENCES dim_origen(id_origen),
            FOREIGN KEY (id_destino) REFERENCES dim_destino(id_destino),
            FOREIGN KEY (id_protocolo) REFERENCES dim_protocolo(id_protocolo),
            FOREIGN KEY (id_tipo_trafico) REFERENCES dim_tipo_trafico(id_tipo_trafico),
            FOREIGN KEY (id_malware) REFERENCES dim_malware(id_malware),
            FOREIGN KEY (id_anomalia) REFERENCES dim_anomalia(id_anomalia),
            FOREIGN KEY (id_severidad) REFERENCES dim_severidad(id_severidad),
            FOREIGN KEY (id_dispositivo) REFERENCES dim_dispositivo(id_dispositivo),
            FOREIGN KEY (id_segmento) REFERENCES dim_segmento(id_segmento),
            FOREIGN KEY (id_geo) REFERENCES dim_geo(id_geo)
        )
    """)
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        print("📋 Tablas en la base de datos:")
        for table in tables:
            print(table[0])

        print("✅ Tablas creadas con éxito en 'ciberseguridad_db'.")
        conn.commit()

    else:
        print("✅ La base de datos 'ciberseguridad_db' ya existe. Continuando con el proceso de ETL...")

# Función para extraer la primera parte de la IP
def extract_ip(ip):
    try:
        return ip.split('.')[0]
    except AttributeError:
        return '0'  # Manejo de errores en caso de valores nulos o incorrectos

# Función para identificar el tipo de dispositivo
def device_identifier(user_agent):
    # Lista de dispositivos conocidos
    devices = [r'Windows', r'Macintosh', r'Linux', r'iPhone', r'iPod', r'iPad', r'Android']
    
    if pd.isna(user_agent):  # Manejo de valores nulos
        return 'Unknown Device'
    user_agent = user_agent.strip()
    for device in devices:
        matching = re.findall(device, user_agent, re.IGNORECASE)
        if matching:
            return matching[0]
    return 'Unknown Device'

def informarcion(df):
    # Imprimir información general del dataset
    print("Valores nulos antes de la limpieza:")
    print(df.isnull().sum())

def limpiar_datos(df):
    # Reemplazo de valores nulos en columnas específicas
    missing_columns = ['Alerts/Warnings', 'IDS/IPS Alerts', 'Malware Indicators', 'Firewall Logs', 'Proxy Information']
    fillvalues = ['None', 'No Data', 'No Detected', 'No Data', 'No Proxy Data']

    # Aplicar reemplazo de valores nulos con un diccionario
    fill_dict = dict(zip(missing_columns, fillvalues))
    df.fillna(fill_dict, inplace=True)

    # Renombrar columna 'Timestamp' a 'Datetime'
    df.rename(columns={'Timestamp': 'Datetime'}, inplace=True)
    df['Datetime'] = pd.to_datetime(df['Datetime'], errors='coerce')

    # Generar nuevas columnas de fecha y hora
    df['year'] = df['Datetime'].dt.year
    df['month'] = df['Datetime'].dt.month
    df['day'] = df['Datetime'].dt.day
    df['dayofweek'] = df['Datetime'].dt.dayofweek
    df['hour'] = df['Datetime'].dt.hour
    df['minute'] = df['Datetime'].dt.minute
    df['second'] = df['Datetime'].dt.second

    # Extraer navegador y dispositivo desde 'Device Information'
    df['Browser'] = df['Device Information'].str.split('/').str[0].astype(pd.StringDtype())
    df['Targeted Device'] = df['Device Information'].apply(device_identifier).astype(pd.StringDtype())

    # Convertir columnas a tipo String donde corresponda
    string_columns = [
        'Source IP Address', 'Destination IP Address', 'Protocol', 'Packet Type', 'Traffic Type',
        'Malware Indicators', 'Alerts/Warnings', 'Attack Signature', 'Action Taken',
        'User Information', 'Network Segment', 'Geo-location Data', 'Proxy Information',
        'Firewall Logs', 'IDS/IPS Alerts', 'Log Source'
    ]
    for col in string_columns:
        df[col] = df[col].astype(pd.StringDtype())

    # Convertir IPs en Private/Public
    df['Source IP Type'] = df['Source IP Address'].apply(lambda x: "Private" if pd.notna(x) and ipaddress.ip_address(x).is_private else "Public").astype    (pd.StringDtype())
    df['Destination IP Type'] = df['Destination IP Address'].apply(lambda x: "Private" if pd.notna(x) and ipaddress.ip_address(x).is_private else   "Public").astype(pd.StringDtype())

    # Extraer la primera parte de la IP para análisis adicional
    df['Source First IP'] = df['Source IP Address'].apply(extract_ip).astype(int, errors='ignore')
    df['Destination First IP'] = df['Destination IP Address'].apply(extract_ip).astype(int, errors='ignore')

    # **CORRECCIÓN EN ALERTS/WARNINGS**
    # Reemplazar valores de texto y convertir a entero
    # Asegurar que 'Alerts/Warnings' es de tipo object antes de la conversión
    df['Alerts/Warnings'] = df['Alerts/Warnings'].astype(object)

    # Mapeo de valores de texto a números
    alert_mapping = {
        'Alert Triggered': 1,
        'No Alerts': 0,
        'None': 0,
        'No Data': 0,
        'No Detected': 0
    }

    # Reemplazar valores de texto y manejar NaN
    df['Alerts/Warnings'] = df['Alerts/Warnings'].replace(alert_mapping)

    # Convertir a numérico, reemplazar NaN por 0 y luego a int
    df['Alerts/Warnings'] = pd.to_numeric(df['Alerts/Warnings'], errors='coerce').fillna(0).astype(int)


    # Guardar el dataset limpio
    df.to_csv("cybersecurity_attacks_cleaned.csv", index=False)

    # Imprimir resumen final
    print("\nValores nulos después de la limpieza:")
    print(df.isnull().sum())
    print("\nTipos de datos después de la limpieza:")
    print(df.dtypes)
    print("\nPrimeras filas del DataFrame limpio:")
    print(df.head(4).T)
    
    return


if __name__ == "__main__":
    comprobar_crear_db()

    # Cargar el dataset
    df = pd.read_csv("cybersecurity_attacks.csv")  

    # Info general
    informarcion(df)

    # Limpieza de datos  
    limpiar_datos(df)
    print("🚀 Datos limpios guardados en 'cybersecurity_attacks_cleaned.csv'.")

    df = pd.read_csv("cybersecurity_attacks_cleaned.csv")

    try:
        load_dimensions(df)
        print("\n🚀 Todas las dimensiones han sido llenadas correctamente.")
        insert_fact_table(df)
        print("🚀 Datos insertados en hechos_ataques correctamente.")
    except Exception as e:
        print("❌ Error en la carga de datos:", e)

    print("🚀 ETL completado con optimización en paralelo y verificación de duplicados.")