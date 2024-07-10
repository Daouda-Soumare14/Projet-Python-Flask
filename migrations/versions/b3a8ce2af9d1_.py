"""empty message

Revision ID: b3a8ce2af9d1
Revises: 725b65b938f2
Create Date: 2024-07-10 03:19:02.688232

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b3a8ce2af9d1'
down_revision = '725b65b938f2'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reset_password_token', sa.String(length=100), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('reset_password_token')

    # ### end Alembic commands ###
