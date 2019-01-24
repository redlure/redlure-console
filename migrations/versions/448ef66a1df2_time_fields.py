"""time fields

Revision ID: 448ef66a1df2
Revises: 
Create Date: 2019-01-24 11:04:13.150525

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '448ef66a1df2'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('campaign', sa.Column('created_at', sa.DateTime(), nullable=True))
    op.add_column('campaign', sa.Column('updated_at', sa.DateTime(), nullable=True))
    op.add_column('email', sa.Column('created_at', sa.DateTime(), nullable=True))
    op.add_column('email', sa.Column('updated_at', sa.DateTime(), nullable=True))
    op.add_column('list', sa.Column('created_at', sa.DateTime(), nullable=True))
    op.add_column('list', sa.Column('updated_at', sa.DateTime(), nullable=True))
    op.add_column('profile', sa.Column('created_at', sa.DateTime(), nullable=True))
    op.add_column('profile', sa.Column('updated_at', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('profile', 'updated_at')
    op.drop_column('profile', 'created_at')
    op.drop_column('list', 'updated_at')
    op.drop_column('list', 'created_at')
    op.drop_column('email', 'updated_at')
    op.drop_column('email', 'created_at')
    op.drop_column('campaign', 'updated_at')
    op.drop_column('campaign', 'created_at')
    # ### end Alembic commands ###
