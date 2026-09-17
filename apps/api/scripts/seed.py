"""CLI Script to bootstrap SentinelForge roles, permissions, and initial admin account."""

import asyncio
from app.db.session import AsyncSessionLocal
from app.services.seed import seed_initial_admin


async def main() -> None:
    print("Beginning SentinelForge RBAC and administrator initialization...")
    async with AsyncSessionLocal() as session:
        admin = await seed_initial_admin(session)
        print(f"Successfully bootstrapped RBAC and administrator: {admin.username} ({admin.email})")


if __name__ == "__main__":
    asyncio.run(main())
