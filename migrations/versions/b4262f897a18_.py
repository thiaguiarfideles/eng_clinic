"""empty message

Revision ID: b4262f897a18
Revises: 303bca86f229
Create Date: 2023-11-06 15:53:56.431905

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b4262f897a18'
down_revision = '303bca86f229'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('entrada_acessorios',
    sa.Column('id_acessorio', sa.Integer(), nullable=False),
    sa.Column('material_id', sa.Integer(), nullable=False),
    sa.Column('fabricante_id', sa.Integer(), nullable=False),
    sa.Column('item_material', sa.String(length=255), nullable=True),
    sa.Column('rm', sa.String(length=255), nullable=True),
    sa.Column('situacao', sa.String(length=50), nullable=True),
    sa.Column('aquisicao', sa.String(length=50), nullable=True),
    sa.Column('setor_id', sa.Integer(), nullable=False),
    sa.Column('cliente_id', sa.Integer(), nullable=False),
    sa.Column('localizacao', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['cliente_id'], ['cliente.id_cliente'], ),
    sa.ForeignKeyConstraint(['fabricante_id'], ['cadfornecedor.id_fornecedor'], ),
    sa.ForeignKeyConstraint(['material_id'], ['material.id'], ),
    sa.ForeignKeyConstraint(['setor_id'], ['setor.id_setor'], ),
    sa.PrimaryKeyConstraint('id_acessorio')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('entrada_acessorios')
    # ### end Alembic commands ###