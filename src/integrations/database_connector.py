"""Database integration for compliance scanning."""

from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
import asyncpg
import aiomysql
import motor.motor_asyncio

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DatabaseConnection:
    """Database connection details."""
    
    db_type: str
    host: str
    port: int
    database: str
    username: str
    password: str


class DatabaseConnector:
    """
    Multi-database integration for compliance scanning.
    
    Supports:
    - PostgreSQL
    - MySQL/MariaDB
    - MongoDB
    - 
    Scans for:
    - PII/PHI data
    - Encryption status
    - Access controls
    - Audit logging
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize database connector."""
        self.config = config or {}
    
    async def scan_postgresql(self, connection: DatabaseConnection) -> Dict[str, Any]:
        """Scan PostgreSQL database for compliance."""
        try:
            logger.info(f"Scanning PostgreSQL database: {connection.database}")
            
            # Connect to database
            conn = await asyncpg.connect(
                host=connection.host,
                port=connection.port,
                user=connection.username,
                password=connection.password,
                database=connection.database
            )
            
            try:
                # Get database size
                size_query = "SELECT pg_database_size(current_database()) as size;"
                size_result = await conn.fetchrow(size_query)
                
                # Get all tables
                tables_query = """
                    SELECT table_name, table_type
                    FROM information_schema.tables
                    WHERE table_schema = 'public'
                """
                tables = await conn.fetch(tables_query)
                
                # Scan each table for PII
                pii_findings = []
                for table in tables:
                    table_name = table['table_name']
                    pii_columns = await self._scan_postgresql_table(conn, table_name)
                    
                    if pii_columns:
                        pii_findings.append({
                            "table": table_name,
                            "pii_columns": pii_columns
                        })
                
                # Check encryption
                encryption_query = """
                    SELECT name, setting 
                    FROM pg_settings 
                    WHERE name LIKE '%ssl%' OR name LIKE '%encrypt%'
                """
                encryption_settings = await conn.fetch(encryption_query)
                
                # Check audit logging
                audit_query = """
                    SELECT name, setting 
                    FROM pg_settings 
                    WHERE name LIKE '%log%'
                """
                audit_settings = await conn.fetch(audit_query)
                
                return {
                    "database_type": "PostgreSQL",
                    "database_name": connection.database,
                    "database_size_bytes": size_result['size'],
                    "total_tables": len(tables),
                    "pii_findings": pii_findings,
                    "encryption_settings": {row['name']: row['setting'] for row in encryption_settings},
                    "audit_settings": {row['name']: row['setting'] for row in audit_settings}
                }
            
            finally:
                await conn.close()
        
        except Exception as e:
            logger.error(f"Failed to scan PostgreSQL database: {e}")
            raise
    
    async def _scan_postgresql_table(self, conn, table_name: str) -> List[str]:
        """Scan PostgreSQL table for PII columns."""
        pii_columns = []
        
        try:
            # Get column information
            columns_query = f"""
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_name = '{table_name}'
            """
            columns = await conn.fetch(columns_query)
            
            # PII column name patterns
            pii_patterns = ['email', 'ssn', 'phone', 'address', 'name', 'dob', 
                           'birth', 'credit_card', 'passport', 'license']
            
            for column in columns:
                column_name = column['column_name'].lower()
                
                if any(pattern in column_name for pattern in pii_patterns):
                    pii_columns.append(column['column_name'])
        
        except Exception as e:
            logger.warning(f"Failed to scan table {table_name}: {e}")
        
        return pii_columns
    
    async def scan_mysql(self, connection: DatabaseConnection) -> Dict[str, Any]:
        """Scan MySQL/MariaDB database for compliance."""
        try:
            logger.info(f"Scanning MySQL database: {connection.database}")
            
            # Connect to database
            conn = await aiomysql.connect(
                host=connection.host,
                port=connection.port,
                user=connection.username,
                password=connection.password,
                db=connection.database
            )
            
            try:
                async with conn.cursor(aiomysql.DictCursor) as cursor:
                    # Get database size
                    await cursor.execute("""
                        SELECT 
                            SUM(data_length + index_length) as size
                        FROM information_schema.tables
                        WHERE table_schema = %s
                    """, (connection.database,))
                    size_result = await cursor.fetchone()
                    
                    # Get all tables
                    await cursor.execute("""
                        SELECT table_name, table_type
                        FROM information_schema.tables
                        WHERE table_schema = %s
                    """, (connection.database,))
                    tables = await cursor.fetchall()
                    
                    # Scan each table for PII
                    pii_findings = []
                    for table in tables:
                        table_name = table['table_name']
                        pii_columns = await self._scan_mysql_table(cursor, connection.database, table_name)
                        
                        if pii_columns:
                            pii_findings.append({
                                "table": table_name,
                                "pii_columns": pii_columns
                            })
                    
                    # Check SSL/TLS
                    await cursor.execute("SHOW VARIABLES LIKE 'have_ssl'")
                    ssl_result = await cursor.fetchone()
                    
                    # Check audit plugin
                    await cursor.execute("SHOW PLUGINS")
                    plugins = await cursor.fetchall()
                    audit_enabled = any('audit' in p['Name'].lower() for p in plugins)
                    
                    return {
                        "database_type": "MySQL",
                        "database_name": connection.database,
                        "database_size_bytes": size_result['size'] or 0,
                        "total_tables": len(tables),
                        "pii_findings": pii_findings,
                        "ssl_enabled": ssl_result['Value'] == 'YES' if ssl_result else False,
                        "audit_enabled": audit_enabled
                    }
            
            finally:
                conn.close()
        
        except Exception as e:
            logger.error(f"Failed to scan MySQL database: {e}")
            raise
    
    async def _scan_mysql_table(self, cursor, database: str, table_name: str) -> List[str]:
        """Scan MySQL table for PII columns."""
        pii_columns = []
        
        try:
            await cursor.execute("""
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = %s AND table_name = %s
            """, (database, table_name))
            
            columns = await cursor.fetchall()
            
            pii_patterns = ['email', 'ssn', 'phone', 'address', 'name', 'dob', 
                           'birth', 'credit_card', 'passport', 'license']
            
            for column in columns:
                column_name = column['column_name'].lower()
                
                if any(pattern in column_name for pattern in pii_patterns):
                    pii_columns.append(column['column_name'])
        
        except Exception as e:
            logger.warning(f"Failed to scan table {table_name}: {e}")
        
        return pii_columns
    
    async def scan_mongodb(self, connection: DatabaseConnection) -> Dict[str, Any]:
        """Scan MongoDB database for compliance."""
        try:
            logger.info(f"Scanning MongoDB database: {connection.database}")
            
            # Connect to MongoDB
            client = motor.motor_asyncio.AsyncIOMotorClient(
                host=connection.host,
                port=connection.port,
                username=connection.username,
                password=connection.password
            )
            
            db = client[connection.database]
            
            try:
                # Get database stats
                stats = await db.command("dbStats")
                
                # Get all collections
                collections = await db.list_collection_names()
                
                # Scan each collection for PII
                pii_findings = []
                for collection_name in collections:
                    collection = db[collection_name]
                    
                    # Sample documents to detect PII fields
                    sample_docs = await collection.find().limit(100).to_list(length=100)
                    
                    pii_fields = set()
                    for doc in sample_docs:
                        pii_fields.update(self._detect_pii_fields(doc))
                    
                    if pii_fields:
                        pii_findings.append({
                            "collection": collection_name,
                            "pii_fields": list(pii_fields)
                        })
                
                # Check if using TLS
                server_status = await db.command("serverStatus")
                security_info = server_status.get('security', {})
                
                return {
                    "database_type": "MongoDB",
                    "database_name": connection.database,
                    "database_size_bytes": stats.get('dataSize', 0),
                    "total_collections": len(collections),
                    "pii_findings": pii_findings,
                    "security": security_info
                }
            
            finally:
                client.close()
        
        except Exception as e:
            logger.error(f"Failed to scan MongoDB database: {e}")
            raise
    
    def _detect_pii_fields(self, document: Dict[str, Any], prefix: str = '') -> List[str]:
        """Recursively detect PII fields in MongoDB document."""
        pii_fields = []
        pii_patterns = ['email', 'ssn', 'phone', 'address', 'name', 'dob', 
                       'birth', 'credit_card', 'passport', 'license']
        
        for key, value in document.items():
            if key == '_id':
                continue
            
            full_key = f"{prefix}.{key}" if prefix else key
            
            # Check field name
            if any(pattern in key.lower() for pattern in pii_patterns):
                pii_fields.append(full_key)
            
            # Recursively check nested documents
            if isinstance(value, dict):
                pii_fields.extend(self._detect_pii_fields(value, full_key))
        
        return pii_fields
    
    async def scan_database(self, connection: DatabaseConnection) -> Dict[str, Any]:
        """Scan database based on type."""
        if connection.db_type.lower() in ['postgresql', 'postgres']:
            return await self.scan_postgresql(connection)
        elif connection.db_type.lower() in ['mysql', 'mariadb']:
            return await self.scan_mysql(connection)
        elif connection.db_type.lower() in ['mongodb', 'mongo']:
            return await self.scan_mongodb(connection)
        else:
            raise ValueError(f"Unsupported database type: {connection.db_type}")
