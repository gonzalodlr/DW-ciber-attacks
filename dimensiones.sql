CREATE TABLE dim_origen (
    id_origen INT AUTO_INCREMENT PRIMARY KEY,
    ip_origen VARCHAR(50) NOT NULL,
    puerto_origen INT,
    proxy BOOLEAN,
    usuario VARCHAR(100)
);

CREATE TABLE dim_destino (
    id_destino INT AUTO_INCREMENT PRIMARY KEY,
    ip_destino VARCHAR(50) NOT NULL,
    puerto_destino INT,
    dispositivo VARCHAR(100)
);

CREATE TABLE dim_protocolo (
    id_protocolo INT AUTO_INCREMENT PRIMARY KEY,
    protocolo VARCHAR(50)
);

CREATE TABLE dim_tipo_trafico (
    id_tipo_trafico INT AUTO_INCREMENT PRIMARY KEY,
    tipo_trafico VARCHAR(50)
);

CREATE TABLE dim_malware (
    id_malware INT AUTO_INCREMENT PRIMARY KEY,
    indicador_malware VARCHAR(255)
);

CREATE TABLE dim_anomalia (
    id_anomalia INT AUTO_INCREMENT PRIMARY KEY,
    score_anomalia FLOAT
);

CREATE TABLE dim_severidad (
    id_severidad INT AUTO_INCREMENT PRIMARY KEY,
    nivel_severidad VARCHAR(50)
);

CREATE TABLE dim_dispositivo (
    id_dispositivo INT AUTO_INCREMENT PRIMARY KEY,
    tipo_dispositivo VARCHAR(100)
);

CREATE TABLE dim_segmento (
    id_segmento INT AUTO_INCREMENT PRIMARY KEY,
    segmento VARCHAR(50)
);

CREATE TABLE dim_geo (
    id_geo INT AUTO_INCREMENT PRIMARY KEY,
    ubicacion VARCHAR(100)
);
