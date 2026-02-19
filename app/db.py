import os
from psycopg_pool import ConnectionPool

DATABASE_URL = os.environ["DATABASE_URL"]
pool = ConnectionPool(conninfo=DATABASE_URL, min_size=1, max_size=5)