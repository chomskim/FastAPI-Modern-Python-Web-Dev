from sqlalchemy import Column, Integer, String
from sqlalchemy.sql.expression import text
from sqlalchemy.sql.sqltypes import TIMESTAMP

from .database import Base

# name, country, area, description, aka
class Creature(Base):
    __tablename__ = "creatures"

    id = Column(Integer, primary_key=True, nullable=False)
    name = Column(String, nullable=False)
    country = Column(String, nullable=False)
    area = Column(String, nullable=False)
    description = Column(String, nullable=False)
    aka = Column(String, nullable=False)
    created_at = Column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )

