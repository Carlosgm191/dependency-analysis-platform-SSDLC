#!/usr/bin/env bash
set -e

python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "Instalación completa de dependencias Python."
echo "Si necesitas usar los scanners trivy o grype, instala sus binarios desde la documentación oficial."