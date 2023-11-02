@echo off

:: Define o diretório do seu virtualenv
set virtualenv_dir=C:\Users\thiago.fideles\Documents\buscalab\venv

:: Ativa o virtualenv
call %virtualenv_dir%\Scripts\activate

:: Define o diretório do seu aplicativo Flask
set flask_app_dir=C:\Users\thiago.fideles\Documents\buscalab

:: Navega até o diretório do aplicativo Flask
cd %flask_app_dir%

:: Verifica se o arquivo de sinalização existe
if exist stop_signal.txt (
    echo Encerrando a aplicação...
    del stop_signal.txt
    exit
)

:: Executa o script Python Flask
python app_lab.py
