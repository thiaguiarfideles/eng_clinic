"""empty message

Revision ID: 6d9b70ac3f47
Revises: dee2d421a1dc
Create Date: 2023-11-01 18:21:59.650796

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6d9b70ac3f47'
down_revision = 'dee2d421a1dc'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('item_material', schema=None) as batch_op:
        batch_op.add_column(sa.Column('quantidade', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('tipo_material_id', sa.Integer(), nullable=False))
        batch_op.create_foreign_key(None, 'material', ['tipo_material_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('item_material', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('tipo_material_id')
        batch_op.drop_column('quantidade')

    # ### end Alembic commands ###
