from peewee import MySQLDatabase

# Database configuration
DATABASE_NAME = 'fastapi'
DATABASE_USER = 'fastapi'
DATABASE_PASSWORD = 'pass1'
DATABASE_HOST = 'mysql'  # or 'localhost'
DATABASE_PORT = 3306

# Connect to the MySQL database
database = MySQLDatabase(
    DATABASE_NAME,
    user=DATABASE_USER,
    password=DATABASE_PASSWORD,
    host=DATABASE_HOST,
    port=DATABASE_PORT
)