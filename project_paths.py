import os
from pathlib import Path

ROOT = Path(os.path.abspath(os.path.dirname(__file__)))
SRC = Path(os.path.abspath(os.path.dirname(__file__))).joinpath("src")
TEMPLATES = Path(os.path.abspath(os.path.dirname(__file__))).joinpath("resources/templates")
STATIC = Path(os.path.abspath(os.path.dirname(__file__))).joinpath("resources/static")
