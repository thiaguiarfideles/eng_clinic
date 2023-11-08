import smtplib
from email.mime.text import MIMEText

# Configurações do servidor de e-mail
EMAIL_FROM = 'seumkt@gmail.com' #email de origem 
EMAIL_TO = 'thiaguiarfideles@live.com' #email de destino
SENHA = 'pmsertnxkggkqqvc'

def enviar_email_administrador(agendamento):
    EMAIL_FROM = 'seumkt@gmail.com'  # Substitua pelo seu email
    EMAIL_TO = 'thiaguiarfideles@live.com'  # Substitua pelo email do administrador
    SENHA = 'pmsertnxkggkqqvc'  # Substitua pela senha do seu email

    assunto = 'Agendamento não atualizado após 24 horas'
    corpo = (
        f'O agendamento com ID {agendamento.id_agendamento} não foi atualizado após 24 horas.\n'
        f'Data do Agendamento: {agendamento.data_agendamento}\n'
        f'Tipo de Serviço: {agendamento.tipo_servico}\n'
        f'Nome do Cliente: {agendamento.cliente.nome_fantasia}\n'
        f'Observações: {agendamento.observacoes}\n'
    )

    msg = MIMEText(corpo)
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    msg['Subject'] = assunto

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_FROM, SENHA)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        server.quit()
        print('Email enviado ao administrador com sucesso!')
    except Exception as e:
        print(f'Erro ao enviar email ao administrador: {str(e)}')

# Exemplo de uso:
# enviar_email_administrador(agendamento_nao_atualizado)
