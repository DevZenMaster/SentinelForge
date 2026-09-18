#!/bin/sh
set -e

# Run database schema migrations
echo "Executing database schema migrations..."
alembic upgrade head

# Bootstrap initial system seed data (RBAC roles, permissions, admin user, detection rules)
echo "Bootstrapping initial system seed data..."
python -c "
import asyncio
from app.db.session import AsyncSessionLocal
from app.services.seed import seed_rbac_and_admin

async def main():
    async with AsyncSessionLocal() as session:
        await seed_rbac_and_admin(session)

asyncio.run(main())
"

echo "Starting SentinelForge API server..."
exec "$@"
