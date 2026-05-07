"""Add Key Management Module with encrypted private keys and key rotation support

Revision ID: 47c8b3f5a9d2
Revises: 261437bc199d
Create Date: 2026-05-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '47c8b3f5a9d2'
down_revision = '261437bc199d'
branch_labels = None
depends_on = None


def upgrade():
    # Add new encrypted private key columns (make them nullable initially for existing records)
    op.add_column('user_keys', sa.Column('rsa_private_key_encrypted', sa.Text(), nullable=True))
    op.add_column('user_keys', sa.Column('ecc_private_key_encrypted', sa.Text(), nullable=True))
    
    # Make old plaintext columns nullable since we're migrating to encrypted storage
    op.alter_column('user_keys', 'rsa_private_key', existing_type=sa.Text(), nullable=True)
    op.alter_column('user_keys', 'ecc_private_key', existing_type=sa.Text(), nullable=True)
    
    # Create KeyArchive table for key rotation history
    op.create_table(
        'key_archive',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('rsa_public_key', sa.Text(), nullable=False),
        sa.Column('rsa_private_key_encrypted', sa.Text(), nullable=False),
        sa.Column('ecc_public_key', sa.Text(), nullable=False),
        sa.Column('ecc_private_key_encrypted', sa.Text(), nullable=False),
        sa.Column('archived_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'version', name='uq_user_version')
    )
    op.create_index(op.f('ix_key_archive_user_id'), 'key_archive', ['user_id'], unique=False)


def downgrade():
    # Drop index if it exists
    try:
        op.drop_index(op.f('ix_key_archive_user_id'), table_name='key_archive')
    except:
        pass  # Index doesn't exist, skip
    
    # Drop table if it exists
    try:
        op.drop_table('key_archive')
    except:
        pass  # Table doesn't exist, skip
    
    # Drop encrypted columns if they exist
    try:
        op.drop_column('user_keys', 'ecc_private_key_encrypted')
    except:
        pass
    
    try:
        op.drop_column('user_keys', 'rsa_private_key_encrypted')
    except:
        pass
    
    try:
        op.drop_column('user_keys', 'ecc_private_key_old')
    except:
        pass
    
    try:
        op.drop_column('user_keys', 'rsa_private_key_old')
    except:
        pass
    
    # Restore NOT NULL constraints on old columns if they still exist
    try:
        op.alter_column('user_keys', 'rsa_private_key', existing_type=sa.Text(), nullable=False)
    except:
        pass
    
    try:
        op.alter_column('user_keys', 'ecc_private_key', existing_type=sa.Text(), nullable=False)
    except:
        pass
