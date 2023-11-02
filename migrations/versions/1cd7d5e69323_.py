"""empty message

Revision ID: 1cd7d5e69323
Revises: 
Create Date: 2023-11-01 17:28:10.000374

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1cd7d5e69323'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('cadfornecedor',
    sa.Column('id_fornecedor', sa.Integer(), nullable=False),
    sa.Column('CNPJ', sa.String(length=130), nullable=False),
    sa.Column('Razao_Social', sa.String(length=100), nullable=False),
    sa.Column('Nome_Fantasia', sa.String(length=100), nullable=False),
    sa.Column('Endereco', sa.String(length=100), nullable=False),
    sa.Column('Numero', sa.String(length=10), nullable=False),
    sa.Column('Complemento', sa.String(length=50), nullable=True),
    sa.Column('Bairro', sa.String(length=50), nullable=False),
    sa.Column('CEP', sa.String(length=9), nullable=False),
    sa.Column('Cidade', sa.String(length=50), nullable=False),
    sa.Column('UF', sa.String(length=2), nullable=False),
    sa.Column('Pais', sa.String(length=50), nullable=False),
    sa.Column('Telefone', sa.String(length=15), nullable=False),
    sa.Column('Ramal', sa.String(length=10), nullable=True),
    sa.Column('Celular', sa.String(length=15), nullable=False),
    sa.Column('Contato', sa.String(length=100), nullable=False),
    sa.Column('Email', sa.String(), nullable=False),
    sa.Column('Site', sa.String(), nullable=True),
    sa.Column('Fabricante', sa.Boolean(), nullable=True),
    sa.Column('Fornecedor', sa.Boolean(), nullable=True),
    sa.Column('Observacoes', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id_fornecedor'),
    sa.UniqueConstraint('id_fornecedor')
    )
    op.create_table('material',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('tipo_material', sa.String(length=20), nullable=False),
    sa.Column('material', sa.String(length=100), nullable=False),
    sa.Column('descricao', sa.String(length=255), nullable=True),
    sa.Column('unidade_medida', sa.String(length=10), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=False),
    sa.Column('password', sa.String(length=500), nullable=False),
    sa.Column('full_name', sa.String(length=100), nullable=False),
    sa.Column('registration_number', sa.String(length=20), nullable=False),
    sa.Column('date_of_birth', sa.Date(), nullable=False),
    sa.Column('is_approved', sa.Boolean(), nullable=True),
    sa.Column('email', sa.String(), nullable=False),
    sa.Column('admin', sa.Boolean(), nullable=False),
    sa.Column('registered_on', sa.DateTime(), nullable=False),
    sa.Column('confirmed_on', sa.DateTime(), nullable=True),
    sa.Column('password_reset_token', sa.String(length=100), nullable=True),
    sa.Column('password_reset_expiration', sa.DateTime(), nullable=True),
    sa.Column('current_password', sa.String(length=500), nullable=True),
    sa.Column('new_password', sa.String(length=500), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('password_reset_token'),
    sa.UniqueConstraint('registration_number'),
    sa.UniqueConstraint('username')
    )
    op.create_table('item_material',
    sa.Column('id_itmaterial', sa.Integer(), nullable=False),
    sa.Column('material_id', sa.Integer(), nullable=False),
    sa.Column('fabricante_id', sa.Integer(), nullable=False),
    sa.Column('modelo', sa.String(length=100), nullable=True),
    sa.Column('complemento', sa.String(length=100), nullable=True),
    sa.Column('foto_material', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['fabricante_id'], ['cadfornecedor.id_fornecedor'], ),
    sa.ForeignKeyConstraint(['material_id'], ['material.id'], ),
    sa.PrimaryKeyConstraint('id_itmaterial')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('item_material')
    op.drop_table('users')
    op.drop_table('material')
    op.drop_table('cadfornecedor')
    # ### end Alembic commands ###