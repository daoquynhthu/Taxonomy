import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

# Mock psycopg2 before importing manager_v2 if it tries to import it at top level (it doesn't, but good practice)
sys.modules['psycopg2'] = MagicMock()
sys.modules['psycopg2.extras'] = MagicMock()

from manager_v2 import PostgreSQLAdapter

class TestPostgreSQLAdapter(unittest.TestCase):
    def setUp(self):
        self.mock_conn = MagicMock()
        self.mock_cursor = MagicMock()
        self.mock_conn.cursor.return_value = self.mock_cursor
        
        with patch('psycopg2.connect', return_value=self.mock_conn):
            self.adapter = PostgreSQLAdapter("dbname=test user=postgres")

    def test_convert_sql(self):
        sql = "SELECT * FROM table WHERE id = ? AND name = ?"
        converted = self.adapter._convert_sql(sql)
        self.assertEqual(converted, "SELECT * FROM table WHERE id = %s AND name = %s")

    def test_execute(self):
        sql = "INSERT INTO table (id, name) VALUES (?, ?)"
        params = (1, "test")
        self.adapter.execute(sql, params)
        
        self.mock_cursor.execute.assert_called_with(
            "INSERT INTO table (id, name) VALUES (%s, %s)",
            params
        )

    def test_fetchone(self):
        self.mock_cursor.fetchone.return_value = {'id': 1, 'name': 'test'}
        
        sql = "SELECT * FROM table WHERE id = ?"
        params = (1,)
        result = self.adapter.fetchone(sql, params)
        
        self.mock_cursor.execute.assert_called_with(
            "SELECT * FROM table WHERE id = %s",
            params
        )
        self.assertEqual(result, {'id': 1, 'name': 'test'})

    def test_fetchall(self):
        self.mock_cursor.fetchall.return_value = [{'id': 1}, {'id': 2}]
        
        sql = "SELECT * FROM table"
        result = self.adapter.fetchall(sql)
        
        self.mock_cursor.execute.assert_called_with(
            "SELECT * FROM table",
            ()
        )
        self.assertEqual(result, [{'id': 1}, {'id': 2}])

if __name__ == '__main__':
    unittest.main()
