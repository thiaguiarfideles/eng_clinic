"""empty message

Revision ID: 0c6a6159d4ad
Revises: 567c01f835a8
Create Date: 2024-01-24 01:09:38.752863

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0c6a6159d4ad'
down_revision = '567c01f835a8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('ordem_servico', schema=None) as batch_op:
        batch_op.alter_column('tipo_os_id',
               existing_type=sa.INTEGER(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('ordem_servico', schema=None) as batch_op:
        batch_op.alter_column('tipo_os_id',
               existing_type=sa.INTEGER(),
               nullable=False)

    # ### end Alembic commands ###
