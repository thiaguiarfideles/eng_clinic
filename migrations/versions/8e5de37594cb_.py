"""empty message

Revision ID: 8e5de37594cb
Revises: 59bd1d0e311f
Create Date: 2023-11-02 12:09:16.313910

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8e5de37594cb'
down_revision = '59bd1d0e311f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('material', schema=None) as batch_op:
        batch_op.add_column(sa.Column('quantidade', sa.Integer(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('material', schema=None) as batch_op:
        batch_op.drop_column('quantidade')

    # ### end Alembic commands ###
