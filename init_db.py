from peewee import MySQLDatabase
from models import User, Task  # Import your models

# Setup database connection
database = MySQLDatabase('fastapi', user='fastapi', password='pass1', host='mysql', port=3306)

# Connect to the database
database.connect()

# Create the tables
database.create_tables([User, Task])

print("Database tables created successfully.")

# Close the connection
database.close()
# *****************************************************************
# * COMMAND -> docker-compose exec fastapi-app python init_db.py  *
# *****************************************************************