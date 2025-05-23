"""Add RecentActivity model

Revision ID: 813bc9a86ac9
Revises: 
Create Date: 2025-05-04 23:23:13.054973

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '813bc9a86ac9'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('recent_activity',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('activity', sa.String(length=120), nullable=False),
    sa.Column('date', sa.String(length=120), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('recent_activity')
    # ### end Alembic commands ###
