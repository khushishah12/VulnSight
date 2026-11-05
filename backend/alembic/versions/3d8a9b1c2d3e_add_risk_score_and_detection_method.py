"""add risk_score and detection_method to findings

Revision ID: 3d8a9b1c2d3e
Revises: 2f6893bcadd8
Create Date: 2026-11-05 17:18:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3d8a9b1c2d3e'
down_revision: Union[str, Sequence[str], None] = '2f6893bcadd8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to include risk_score and detection_method."""
    op.add_column('findings', sa.Column('risk_score', sa.Float(), nullable=True))
    op.add_column('findings', sa.Column('detection_method', sa.String(length=50), nullable=True))
    op.create_index('ix_findings_risk_score', 'findings', ['risk_score'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_findings_risk_score', table_name='findings')
    op.drop_column('findings', 'detection_method')
    op.drop_column('findings', 'risk_score')
