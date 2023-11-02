@echo off
start iexplore http://127.0.0.1:5000/execute_query
timeout /t 0
start iexplore http://127.0.0.1:5000/execute_query_df
timeout /t 0
location.reload()
@echo on
call C:\Users\thiago.fideles\Documents\buscalab\venv\Scripts\activate
call python C:\Users\thiago.fideles\Documents\buscalab\escreve_exame.py run

