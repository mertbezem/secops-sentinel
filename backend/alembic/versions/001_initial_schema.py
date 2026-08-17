"""Initial schema creation

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-08-14 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = '001_initial_schema'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. machines
    op.create_table(
        'machines',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('criticality', sa.String(length=50), nullable=False, server_default='MEDIUM'),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('event_count', sa.Integer(), nullable=False, server_default='0'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_machines_name'), 'machines', ['name'], unique=True)

    # 2. message_templates
    op.create_table(
        'message_templates',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('template_hash', sa.String(length=64), nullable=False),
        sa.Column('template_text', sa.Text(), nullable=False),
        sa.Column('param_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('occurrence_count', sa.Integer(), nullable=False, server_default='0'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('template_hash')
    )
    op.create_index(op.f('ix_message_templates_template_hash'), 'message_templates', ['template_hash'], unique=True)

    # 3. rules
    op.create_table(
        'rules',
        sa.Column('code', sa.String(length=50), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('params', sa.JSON(), nullable=False),
        sa.Column('weight', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('mitre_techniques', sa.JSON(), nullable=False),
        sa.Column('is_demo', sa.Boolean(), nullable=False, server_default='false'),
        sa.PrimaryKeyConstraint('code')
    )

    # 4. incidents
    op.create_table(
        'incidents',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='OPEN'),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=False),
        sa.Column('machine_id', sa.Integer(), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finding_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('mitre_techniques', sa.JSON(), nullable=False),
        sa.Column('assignee', sa.String(length=100), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['machine_id'], ['machines.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_incidents_status_sev_ts', 'incidents', ['status', 'severity', sa.text('first_seen DESC')], unique=False)

    # 5. events
    op.create_table(
        'events',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('machine_id', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=False),
        sa.Column('category', sa.String(length=255), nullable=True),
        sa.Column('entry_type', sa.String(length=50), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('template_id', sa.Integer(), nullable=True),
        sa.Column('ts_utc', sa.DateTime(timezone=True), nullable=False),
        sa.Column('hour_of_day', sa.Integer(), nullable=False),
        sa.Column('day_of_week', sa.Integer(), nullable=False),
        sa.Column('is_business_hours', sa.Boolean(), nullable=False),
        sa.Column('country', sa.String(length=100), nullable=True),
        sa.Column('region_name', sa.String(length=100), nullable=True),
        sa.Column('city', sa.String(length=100), nullable=True),
        sa.Column('extracted_entities', sa.JSON(), nullable=False),
        sa.Column('dedup_hash', sa.String(length=64), nullable=False),
        sa.Column('ingested_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['machine_id'], ['machines.id'], ),
        sa.ForeignKeyConstraint(['template_id'], ['message_templates.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('dedup_hash')
    )
    op.create_index(op.f('ix_events_dedup_hash'), 'events', ['dedup_hash'], unique=True)
    op.create_index('idx_events_machine_ts', 'events', ['machine_id', sa.text('ts_utc DESC')], unique=False)
    op.create_index('idx_events_source_entry_type', 'events', ['source', 'entry_type'], unique=False)

    # 6. findings
    op.create_table(
        'findings',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('rule_code', sa.String(length=50), nullable=False),
        sa.Column('machine_id', sa.Integer(), nullable=False),
        sa.Column('ts_utc', sa.DateTime(timezone=True), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=False),
        sa.Column('reasons', sa.JSON(), nullable=False),
        sa.Column('evidence_event_ids', sa.JSON(), nullable=False),
        sa.Column('incident_id', sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ),
        sa.ForeignKeyConstraint(['machine_id'], ['machines.id'], ),
        sa.ForeignKeyConstraint(['rule_code'], ['rules.code'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_findings_machine_ts', 'findings', ['machine_id', sa.text('ts_utc DESC')], unique=False)

    # 7. baselines
    op.create_table(
        'baselines',
        sa.Column('machine_id', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=False),
        sa.Column('metric', sa.String(length=100), nullable=False),
        sa.Column('window_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('window_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('mean', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('stddev', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('sample_count', sa.Integer(), nullable=False, server_default='0'),
        sa.ForeignKeyConstraint(['machine_id'], ['machines.id'], ),
        sa.PrimaryKeyConstraint('machine_id', 'source', 'metric')
    )


def downgrade() -> None:
    op.drop_table('baselines')
    op.drop_table('findings')
    op.drop_table('events')
    op.drop_table('incidents')
    op.drop_table('rules')
    op.drop_table('message_templates')
    op.drop_table('machines')
