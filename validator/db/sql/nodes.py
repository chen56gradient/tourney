import datetime
from typing import List
from typing import Optional

from asyncpg.connection import Connection
from fiber import SubstrateInterface
from fiber.chain.models import Node

from core.constants import NETUID
from validator.db import constants as dcst
from validator.db.database import PSQLDB
from validator.utils.logging import get_logger
from validator.utils.query_substrate import query_substrate


logger = get_logger(__name__)

async def _blacklist_nodes(hotkeys: list[str], psql_db: PSQLDB) -> None:
    logger.info(f"NODES ARE BEING BLACKLISTED {hotkeys}")
    async with await psql_db.connection() as connection:
        connection: Connection
        query = f"""
            UPDATE {dcst.NODES_TABLE}
            SET is_blacklisted = TRUE
            WHERE {dcst.HOTKEY} = ANY($1)
        """
        await connection.execute(query, hotkeys)

async def get_eligible_nodes(psql_db: PSQLDB) -> List[Node]:
    """
    Get all nodes that either:
    a) Do not have any entries in the task_nodes table (new nodes with no scores)
    b) Have at least one entry in the task_nodes table with a task_node_quality_score > 0
    c) Have entries in task_nodes but all scores are NULL (not yet evaluated nodes)
    This only excludes nodes that have been scored but ALL their non-NULL scores are ≤ 0
    """
    logger.info("Getting eligible nodes (new nodes, nodes with NULL scores, or nodes with positive scores)")
    async with await psql_db.connection() as connection:
        connection: Connection
        query = f"""
            SELECT n.* FROM {dcst.NODES_TABLE} n
            WHERE n.{dcst.NETUID} = $1
            AND n.is_blacklisted = FALSE
            AND (
                -- Condition a: No entries in task_nodes table
                NOT EXISTS (
                    SELECT 1 FROM {dcst.TASK_NODES_TABLE} tn
                    WHERE tn.{dcst.HOTKEY} = n.{dcst.HOTKEY}
                )
                OR
                -- Condition b: At least one entry with quality_score > 0
                EXISTS (
                    SELECT 1 FROM {dcst.TASK_NODES_TABLE} tn
                    WHERE tn.{dcst.HOTKEY} = n.{dcst.HOTKEY}
                    AND tn.{dcst.TASK_NODE_QUALITY_SCORE} > 0
                )
                OR
                -- Condition c: Has entries but all scores are NULL
                (
                    EXISTS (
                        SELECT 1 FROM {dcst.TASK_NODES_TABLE} tn
                        WHERE tn.{dcst.HOTKEY} = n.{dcst.HOTKEY}
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM {dcst.TASK_NODES_TABLE} tn
                        WHERE tn.{dcst.HOTKEY} = n.{dcst.HOTKEY}
                        AND tn.{dcst.TASK_NODE_QUALITY_SCORE} IS NOT NULL
                    )
                )
            )
        """
        rows = await connection.fetch(query, NETUID)
        eligible_nodes = [Node(**dict(row)) for row in rows]
        logger.info(f"Found {len(eligible_nodes)} eligible nodes")
        return eligible_nodes

async def get_all_nodes(psql_db: PSQLDB) -> List[Node]:
    """Get all nodes for the current NETUID"""
    logger.info("Attempting to get all nodes")
    async with await psql_db.connection() as connection:
        connection: Connection
        query = f"""
            SELECT * FROM {dcst.NODES_TABLE}
            WHERE {dcst.NETUID} = $1
        """
        rows = await connection.fetch(query, NETUID)
        nodes = [Node(**dict(row)) for row in rows]
        logger.info(f"Here is the list of nodes {nodes}")
        return nodes


async def insert_nodes(connection: Connection, nodes: list[Node]) -> None:
    logger.info(f"Inserting {len(nodes)} nodes into {dcst.NODES_TABLE}...")
    await connection.executemany(
        f"""
        INSERT INTO {dcst.NODES_TABLE} (
            {dcst.HOTKEY},
            {dcst.COLDKEY},
            {dcst.NODE_ID},
            {dcst.INCENTIVE},
            {dcst.NETUID},
            {dcst.ALPHA_STAKE},
            {dcst.TAO_STAKE},
            {dcst.STAKE},
            {dcst.TRUST},
            {dcst.VTRUST},
            {dcst.LAST_UPDATED},
            {dcst.IP},
            {dcst.IP_TYPE},
            {dcst.PORT},
            {dcst.PROTOCOL}
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        """,
        [
            (
                node.hotkey,
                node.coldkey,
                node.node_id,
                node.incentive,
                node.netuid,
                node.alpha_stake,
                node.tao_stake,
                node.stake,
                node.trust,
                node.vtrust,
                node.last_updated,
                node.ip,
                node.ip_type,
                node.port,
                node.protocol,
            )
            for node in nodes
        ],
    )


async def get_node_by_hotkey(hotkey: str, psql_db: PSQLDB) -> Optional[Node]:
    """Get node by hotkey for the current NETUID"""
    async with await psql_db.connection() as connection:
        connection: Connection
        query = f"""
            SELECT * FROM {dcst.NODES_TABLE}
            WHERE {dcst.HOTKEY} = $1 AND {dcst.NETUID} = $2
        """
        row = await connection.fetchrow(query, hotkey, NETUID)
        if row:
            return Node(**dict(row))
        return None


async def update_our_vali_node_in_db(connection: Connection, ss58_address: str) -> None:
    """Update validator node for the current NETUID"""
    query = f"""
        UPDATE {dcst.NODES_TABLE}
        SET {dcst.OUR_VALIDATOR} = true
        WHERE {dcst.HOTKEY} = $1 AND {dcst.NETUID} = $2
    """
    await connection.execute(query, ss58_address, NETUID)


async def get_vali_ss58_address(psql_db: PSQLDB) -> str | None:
    """Get validator SS58 address for the current NETUID"""
    async with await psql_db.connection() as connection:
        connection: Connection
        query = f"""
            SELECT {dcst.HOTKEY}
            FROM {dcst.NODES_TABLE}
            WHERE {dcst.OUR_VALIDATOR} = true AND {dcst.NETUID} = $1
        """
        row = await connection.fetchrow(query, NETUID)
        if row is None:
            logger.error(f"Cannot find validator node for netuid {NETUID} in the DB. Maybe control node is still syncing?")
            return None
        return row[dcst.HOTKEY]


async def get_last_updated_time_for_nodes(connection: Connection) -> datetime.datetime | None:
    """Get last updated time for nodes in the current NETUID"""
    query = f"""
        SELECT MAX({dcst.CREATED_TIMESTAMP})
        FROM {dcst.NODES_TABLE}
        WHERE {dcst.NETUID} = $1
    """
    return await connection.fetchval(query, NETUID)


async def migrate_nodes_to_history(connection: Connection) -> None:
    """Migrate nodes to history table for the current NETUID"""
    logger.info(f"Migrating nodes to history for NETUID {NETUID}")
    await connection.execute(
        f"""
            INSERT INTO {dcst.NODES_HISTORY_TABLE} (
                {dcst.HOTKEY},
                {dcst.COLDKEY},
                {dcst.INCENTIVE},
                {dcst.NETUID},
                {dcst.ALPHA_STAKE},
                {dcst.TAO_STAKE},
                {dcst.STAKE},
                {dcst.TRUST},
                {dcst.VTRUST},
                {dcst.LAST_UPDATED},
                {dcst.IP},
                {dcst.IP_TYPE},
                {dcst.PORT},
                {dcst.PROTOCOL},
                {dcst.NODE_ID}
            )
            SELECT
                {dcst.HOTKEY},
                {dcst.COLDKEY},
                {dcst.INCENTIVE},
                {dcst.NETUID},
                {dcst.ALPHA_STAKE},
                {dcst.TAO_STAKE},
                {dcst.STAKE},
                {dcst.TRUST},
                {dcst.VTRUST},
                {dcst.LAST_UPDATED},
                {dcst.IP},
                {dcst.IP_TYPE},
                {dcst.PORT},
                {dcst.PROTOCOL},
                {dcst.NODE_ID}
            FROM {dcst.NODES_TABLE}
            WHERE {dcst.NETUID} = $1
        """,
        NETUID,
    )
    logger.debug(f"Truncating node info table for NETUID {NETUID}")
    await connection.execute(f"DELETE FROM {dcst.NODES_TABLE} WHERE {dcst.NETUID} = $1", NETUID)

    # Get length of nodes table to check if migration was successful
    query = f"""
        SELECT COUNT(*) FROM {dcst.NODES_TABLE}
        WHERE {dcst.NETUID} = $1
    """
    node_entries = await connection.fetchval(query, NETUID)
    logger.debug(f"Node entries: {node_entries}")


async def get_vali_node_id(substrate: SubstrateInterface, ss58_address: str) -> str | None:
    _, uid = query_substrate(substrate, "SubtensorModule", "Uids", [NETUID, ss58_address], return_value=True)
    return uid


async def get_node_id_by_hotkey(hotkey: str, psql_db: PSQLDB) -> int | None:
    """Get node_id by hotkey for the current NETUID"""
    async with await psql_db.connection() as connection:
        connection: Connection
        query = f"""
            SELECT {dcst.NODE_ID} FROM {dcst.NODES_TABLE}
            WHERE {dcst.HOTKEY} = $1 AND {dcst.NETUID} = $2
        """
        return await connection.fetchval(query, hotkey, NETUID)

async def insert_nodes_with_blacklist(connection, nodes, blacklisted_nodes):
    """Insert nodes while preserving blacklist status"""
    # Assuming this uses some kind of bulk insert
    # You'll need to adapt this to match your actual insert_nodes implementation

    for chunk in chunks(nodes, 1000):  # Process in chunks if you have many nodes
        values = []
        for node in chunk:
            # Convert node to dict or tuple based on your insert method
            node_data = node.model_dump(mode="json")

            # Add is_blacklisted value from our lookup
            is_blacklisted = blacklisted_nodes.get((node.hotkey, node.netuid), False)

            # Add to values list (format depends on your implementation)
            values.append({**node_data, "is_blacklisted": is_blacklisted})

        # Perform the insert with the preserved blacklist status
        # This example uses a format compatible with asyncpg
        columns = list(values[0].keys())
        column_str = ", ".join(columns)
        placeholder_str = ", ".join(f"${i+1}" for i in range(len(columns)))

        query = f"""
        INSERT INTO nodes ({column_str})
        VALUES ({placeholder_str})
        ON CONFLICT (hotkey, netuid) DO UPDATE SET
        {', '.join(f"{col} = EXCLUDED.{col}" for col in columns if col not in ['hotkey', 'netuid'])}
        """

        for value_dict in values:
            value_tuple = tuple(value_dict[col] for col in columns)
            await connection.execute(query, *value_tuple)
