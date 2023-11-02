@echo off

:: Define o diret�rio do seu virtualenv
set virtualenv_dir=C:\Users\thiago.fideles\Documents\buscalab\venv

:: Ativa o virtualenv
call %virtualenv_dir%\Scripts\activate

:: Define o diret�rio do seu aplicativo Flask
set flask_app_dir=C:\Users\thiago.fideles\Documents\buscalab

:: Navega at� o diret�rio do aplicativo Flask
cd %flask_app_dir%

:: Verifica se o arquivo de sinaliza��o existe
if exist stop_signal.txt (
    echo Encerrando a aplica��o...
    del stop_signal.txt
    exit
)

:: Executa o script Python Flask
python app_lab.py
