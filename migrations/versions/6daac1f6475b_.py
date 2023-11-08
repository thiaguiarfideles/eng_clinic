"""empty message

Revision ID: 6daac1f6475b
Revises: b4262f897a18
Create Date: 2023-11-07 15:05:43.031971

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6daac1f6475b'
down_revision = 'b4262f897a18'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('agendamento',
    sa.Column('id_agendamento', sa.Integer(), nullable=False),
    sa.Column('data_agendamento', sa.Date(), nullable=False),
    sa.Column('data_lancamento', sa.DateTime(), nullable=False),
    sa.Column('tipo_servico', sa.String(length=20), nullable=False),
    sa.Column('cliente_id', sa.Integer(), nullable=False),
    sa.Column('observacoes', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['cliente_id'], ['cliente.id_cliente'], ),
    sa.PrimaryKeyConstraint('id_agendamento')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('agendamento')
    # ### end Alembic commands ###