Команда для сборки кода (main.py)\
\
python -m nuitka --standalone --onefile --windows-console-mode=disable --disable-cache=ccache --enable-plugin=pyqt5 --output-dir=build --output-file=UserManagementApp main.py
