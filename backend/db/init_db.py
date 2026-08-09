"""Initialize all tables (alerts, settings, chat) + MITRE index tables."""
from .models import Base, engine
from ..mitre.attack_db import init as init_mitre


def init_all() -> None:
    Base.metadata.create_all(engine)
    init_mitre()


if __name__ == "__main__":
    init_all()
    print("database ready")
