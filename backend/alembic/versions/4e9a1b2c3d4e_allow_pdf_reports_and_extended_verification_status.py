"""allow pdf reports and extended verification status

Revision ID: 4e9a1b2c3d4e
Revises: 3d8a9b1c2d3e
Create Date: 2026-11-05 18:37:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4e9a1b2c3d4e'
down_revision: Union[str, Sequence[str], None] = '3d8a9b1c2d3e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to allow pdf format and extended verification statuses."""
    # Update format_allowed on reports
    op.drop_constraint('format_allowed', 'reports', type_='check')
    op.create_check_constraint(
        'format_allowed',
        'reports',
        "format IN ('html', 'json', 'pdf')"
    )

    # Update status_allowed on verification_runs
    op.drop_constraint('status_allowed', 'verification_runs', type_='check')
    op.create_check_constraint(
        'status_allowed',
        'verification_runs',
        "status IN ('pending', 'running', 'passed', 'failed', 'error', 'cancelled', 'fixed', 'persists', 'inconclusive')"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('status_allowed', 'verification_runs', type_='check')
    op.create_check_constraint(
        'status_allowed',
        'verification_runs',
        "status IN ('pending', 'running', 'passed', 'failed', 'error', 'cancelled')"
    )

    op.drop_constraint('format_allowed', 'reports', type_='check')
    op.create_check_constraint(
        'format_allowed',
        'reports',
        "format IN ('html', 'json')"
    )
