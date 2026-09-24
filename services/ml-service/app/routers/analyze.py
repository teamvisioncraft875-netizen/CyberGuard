"""
Re-export analyzeRouter for backwards compatibility with app.main.
"""
from app.routers.analyzeRouter import router

__all__ = ["router"]
