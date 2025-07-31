import psycopg2

def get_db_connection():
    conn = psycopg2.connect(
        host='localhost',
        dbname='Threat_data',
        user='postgres',
        password='kajal@123',
        port=5432
    )
    return conn
