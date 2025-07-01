#!/usr/bin/env python3
"""
BackdoorBuster Database Migration Script
Manages database schema migrations for PostgreSQL
"""

import os
import sys
import json
import psycopg2
from pathlib import Path
from datetime import datetime
from termcolor import colored, cprint

class DatabaseMigrator:
    """Handles database migrations for BackdoorBuster"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent.absolute()
        self.config_file = self.base_dir / "config.json"
        self.schema_file = self.base_dir / "data" / "backdoor_db.sql"
        
        self.db_connection = None
        self.config = {}
        
    def load_config(self):
        """Load database configuration"""
        try:
            if not self.config_file.exists():
                cprint("❌ Configuration file not found. Please run setup first.", 'red')
                return False
                
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
            
            return True
            
        except Exception as e:
            cprint(f"❌ Failed to load configuration: {e}", 'red')
            return False
    
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            db_config = self.config.get('database', {})
            self.db_connection = psycopg2.connect(
                host=db_config.get('host', 'localhost'),
                port=db_config.get('port', 5432),
                database=db_config.get('database', 'backdoorbuster'),
                user=db_config.get('user', 'postgres'),
                password=db_config.get('password', '')
            )
            self.db_connection.autocommit = True
            cprint("✅ Connected to PostgreSQL database", 'green')
            return True
            
        except Exception as e:
            cprint(f"❌ Database connection failed: {e}", 'red')
            return False
    
    def check_migration_table(self):
        """Create migration tracking table if it doesn't exist"""
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    id SERIAL PRIMARY KEY,
                    version VARCHAR(50) UNIQUE NOT NULL,
                    description TEXT,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT TRUE
                )
            """)
            cursor.close()
            return True
            
        except Exception as e:
            cprint(f"❌ Failed to create migration table: {e}", 'red')
            return False
    
    def get_current_version(self):
        """Get current database schema version"""
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
                SELECT version FROM schema_migrations 
                WHERE success = TRUE 
                ORDER BY applied_at DESC 
                LIMIT 1
            """)
            result = cursor.fetchone()
            cursor.close()
            
            return result[0] if result else None
            
        except Exception as e:
            cprint(f"❌ Failed to get current version: {e}", 'red')
            return None
    
    def apply_schema(self):
        """Apply the complete database schema"""
        try:
            cprint("🔄 Applying database schema...", 'blue')
            
            # Read schema file
            if not self.schema_file.exists():
                cprint(f"❌ Schema file not found: {self.schema_file}", 'red')
                return False
            
            with open(self.schema_file, 'r') as f:
                schema_sql = f.read()
            
            # Split into individual statements
            statements = [stmt.strip() for stmt in schema_sql.split(';') if stmt.strip()]
            
            cursor = self.db_connection.cursor()
            
            for i, statement in enumerate(statements):
                try:
                    # Skip comments and empty statements
                    if statement.startswith('--') or not statement:
                        continue
                    
                    cursor.execute(statement)
                    print(f"Executed statement {i+1}/{len(statements)}", end='\r')
                    
                except Exception as e:
                    cprint(f"\n⚠️  Warning in statement {i+1}: {e}", 'yellow')
                    continue
            
            cursor.close()
            
            # Record migration
            cursor = self.db_connection.cursor()
            cursor.execute("""
                INSERT INTO schema_migrations (version, description)
                VALUES (%s, %s)
                ON CONFLICT (version) DO UPDATE SET
                applied_at = CURRENT_TIMESTAMP,
                success = TRUE
            """, ("1.0.0", "Initial schema deployment"))
            cursor.close()
            
            cprint("\n✅ Database schema applied successfully", 'green')
            return True
            
        except Exception as e:
            cprint(f"❌ Schema application failed: {e}", 'red')
            return False
    
    def migrate_to_version(self, target_version):
        """Migrate database to specific version"""
        current_version = self.get_current_version()
        
        cprint(f"🔄 Current version: {current_version or 'None'}", 'blue')
        cprint(f"🎯 Target version: {target_version}", 'blue')
        
        if current_version == target_version:
            cprint("✅ Database is already at target version", 'green')
            return True
        
        # For now, we only support migrating to 1.0.0
        if target_version == "1.0.0":
            return self.apply_schema()
        else:
            cprint(f"❌ Migration to version {target_version} not supported", 'red')
            return False
    
    def backup_database(self):
        """Create a database backup before migration"""
        try:
            backup_dir = self.base_dir / "backups"
            backup_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = backup_dir / f"backup_{timestamp}.sql"
            
            db_config = self.config.get('database', {})
            
            # Use pg_dump to create backup
            import subprocess
            
            cmd = [
                'pg_dump',
                '-h', db_config.get('host', 'localhost'),
                '-p', str(db_config.get('port', 5432)),
                '-U', db_config.get('user', 'postgres'),
                '-d', db_config.get('database', 'backdoorbuster'),
                '-f', str(backup_file),
                '--no-password'
            ]
            
            # Set PGPASSWORD environment variable
            env = os.environ.copy()
            env['PGPASSWORD'] = db_config.get('password', '')
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode == 0:
                cprint(f"✅ Database backup created: {backup_file}", 'green')
                return str(backup_file)
            else:
                cprint(f"⚠️  Backup failed: {result.stderr}", 'yellow')
                cprint("Continuing without backup...", 'yellow')
                return None
                
        except Exception as e:
            cprint(f"⚠️  Backup failed: {e}", 'yellow')
            cprint("Continuing without backup...", 'yellow')
            return None
    
    def rollback_migration(self, backup_file=None):
        """Rollback to previous state"""
        if not backup_file or not Path(backup_file).exists():
            cprint("❌ No backup file available for rollback", 'red')
            return False
        
        try:
            cprint(f"🔄 Rolling back from backup: {backup_file}", 'blue')
            
            db_config = self.config.get('database', {})
            
            # Drop and recreate database
            cursor = self.db_connection.cursor()
            cursor.execute(f"DROP SCHEMA public CASCADE")
            cursor.execute(f"CREATE SCHEMA public")
            cursor.close()
            
            # Restore from backup
            import subprocess
            
            cmd = [
                'psql',
                '-h', db_config.get('host', 'localhost'),
                '-p', str(db_config.get('port', 5432)),
                '-U', db_config.get('user', 'postgres'),
                '-d', db_config.get('database', 'backdoorbuster'),
                '-f', backup_file,
                '--no-password'
            ]
            
            env = os.environ.copy()
            env['PGPASSWORD'] = db_config.get('password', '')
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode == 0:
                cprint("✅ Database rollback completed", 'green')
                return True
            else:
                cprint(f"❌ Rollback failed: {result.stderr}", 'red')
                return False
                
        except Exception as e:
            cprint(f"❌ Rollback failed: {e}", 'red')
            return False
    
    def verify_schema(self):
        """Verify database schema integrity"""
        try:
            cprint("🔍 Verifying database schema...", 'blue')
            
            cursor = self.db_connection.cursor()
            
            # Check required tables
            required_tables = [
                'threats', 'mitigations', 'forensics', 'sessions',
                'system_config', 'scan_jobs', 'yara_rules', 'quarantine',
                'audit_log', 'network_events', 'file_hashes', 'schema_migrations'
            ]
            
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            """)
            
            existing_tables = [row[0] for row in cursor.fetchall()]
            
            missing_tables = set(required_tables) - set(existing_tables)
            
            if missing_tables:
                cprint(f"❌ Missing tables: {', '.join(missing_tables)}", 'red')
                return False
            
            # Check indexes
            cursor.execute("""
                SELECT indexname 
                FROM pg_indexes 
                WHERE schemaname = 'public'
            """)
            
            indexes = [row[0] for row in cursor.fetchall()]
            cprint(f"📊 Found {len(indexes)} indexes", 'blue')
            
            # Check views
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.views 
                WHERE table_schema = 'public'
            """)
            
            views = [row[0] for row in cursor.fetchall()]
            cprint(f"👁️  Found {len(views)} views", 'blue')
            
            cursor.close()
            
            cprint("✅ Database schema verification completed", 'green')
            cprint(f"   Tables: {len(existing_tables)}", 'white')
            cprint(f"   Indexes: {len(indexes)}", 'white')
            cprint(f"   Views: {len(views)}", 'white')
            
            return True
            
        except Exception as e:
            cprint(f"❌ Schema verification failed: {e}", 'red')
            return False
    
    def show_migration_history(self):
        """Show migration history"""
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
                SELECT version, description, applied_at, success
                FROM schema_migrations
                ORDER BY applied_at DESC
            """)
            
            migrations = cursor.fetchall()
            cursor.close()
            
            if not migrations:
                cprint("📋 No migrations found", 'blue')
                return
            
            cprint("📋 Migration History:", 'cyan', attrs=['bold'])
            
            for version, description, applied_at, success in migrations:
                status = "✅" if success else "❌"
                cprint(f"   {status} {version} - {description}", 'white')
                cprint(f"      Applied: {applied_at}", 'white')
                print()
            
        except Exception as e:
            cprint(f"❌ Failed to show migration history: {e}", 'red')
    
    def run(self, command=None, target_version=None):
        """Main migration runner"""
        if not self.load_config():
            return False
        
        if not self.connect_db():
            return False
        
        if not self.check_migration_table():
            return False
        
        if command == "status":
            current_version = self.get_current_version()
            cprint(f"📊 Current database version: {current_version or 'None'}", 'blue')
            self.show_migration_history()
            
        elif command == "migrate":
            # Create backup before migration
            backup_file = self.backup_database()
            
            # Perform migration
            target = target_version or "1.0.0"
            success = self.migrate_to_version(target)
            
            if success:
                self.verify_schema()
            else:
                cprint("❌ Migration failed", 'red')
                
                if backup_file:
                    rollback = input("🔄 Would you like to rollback? (y/N): ")
                    if rollback.lower() == 'y':
                        self.rollback_migration(backup_file)
        
        elif command == "verify":
            self.verify_schema()
        
        elif command == "history":
            self.show_migration_history()
        
        else:
            cprint("Usage: python migrate.py <command> [version]", 'cyan')
            cprint("Commands:", 'white')
            cprint("  status   - Show current migration status", 'white')
            cprint("  migrate  - Migrate to latest or specified version", 'white')
            cprint("  verify   - Verify database schema integrity", 'white')
            cprint("  history  - Show migration history", 'white')
        
        if self.db_connection:
            self.db_connection.close()
        
        return True

if __name__ == "__main__":
    migrator = DatabaseMigrator()
    
    command = sys.argv[1] if len(sys.argv) > 1 else None
    version = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        migrator.run(command, version)
    except KeyboardInterrupt:
        cprint("\n❌ Migration interrupted by user", 'red')
        sys.exit(1)
    except Exception as e:
        cprint(f"❌ Migration failed: {e}", 'red')
        sys.exit(1)
