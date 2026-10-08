@echo off
REM Run once from the Aegis folder. Produces dist\Aegis.exe, which asks for Administrator when opened.
pip install pyinstaller pywebview flask requests
pyinstaller --onefile --windowed --uac-admin --name Aegis --add-data "static;static" --add-data "traps.txt;." aegis_desktop.py
copy /Y config.json dist\config.json
echo.
echo Done. Open dist\Aegis.exe (config.json sits next to it).
pause
