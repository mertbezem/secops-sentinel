import csv
import datetime
import io
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import logger
from app.ingestion.entity_extractor import extract_entities
from app.ingestion.normalizer import compute_derived_fields
from app.ingestion.template_extractor import extract_template
from app.models.models import Event, Machine, MessageTemplate


def _ensure_utc(dt: datetime.datetime) -> datetime.datetime:
    if dt is None:
        return datetime.datetime.now(datetime.UTC)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.UTC)
    return dt


def load_csv_data(
    db: Session,
    file_obj: io.TextIOBase,
    chunk_size: int = settings.INGEST_BATCH_SIZE
) -> dict[str, Any]:
    """
    Ingests CSV log stream into database in chunks.
    Performs:
    1. Machine creation/lookup
    2. Deduplication using SHA-256 dedup_hash
    3. Template extraction & lookup/creation
    4. Structured Entity extraction
    5. Derived fields computation (ts_utc, business hours)
    6. Bulk database insert
    """
    reader = csv.reader(file_obj)
    try:
        headers = next(reader)
    except StopIteration:
        return {
            "total_processed": 0,
            "new_events": 0,
            "duplicates_skipped": 0,
            "templates_created": 0,
            "message": "Empty CSV file"
        }

    # Map column headers
    header_map = {col.strip().lower(): idx for idx, col in enumerate(headers)}
    
    col_machine = header_map.get("machinename", 1)
    col_category = header_map.get("category", 2)
    col_entrytype = header_map.get("entrytype", 3)
    col_message = header_map.get("message", 4)
    col_source = header_map.get("source", 5)
    col_time = header_map.get("timegenerated", 6)
    col_country = header_map.get("country", 7)
    col_region = header_map.get("regionname", 8)
    col_city = header_map.get("city", 9)

    # Pre-cache existing machines and template hashes
    existing_machines: dict[str, Machine] = {
        m.name: m for m in db.scalars(select(Machine)).all()
    }
    existing_templates: dict[str, MessageTemplate] = {
        t.template_hash: t for t in db.scalars(select(MessageTemplate)).all()
    }
    existing_dedup_hashes: set[str] = set(
        db.scalars(select(Event.dedup_hash)).all()
    )

    total_processed = 0
    new_events_count = 0
    duplicates_count = 0
    templates_created_count = 0

    pending_events = []
    
    for row in reader:
        if not row or len(row) <= max(col_machine, col_message, col_source, col_time):
            continue

        total_processed += 1

        machine_name = row[col_machine].strip() or "UNKNOWN_HOST"
        source = row[col_source].strip() or "UNKNOWN_SOURCE"
        category = row[col_category].strip() if col_category < len(row) else ""
        entry_type = row[col_entrytype].strip() or "Information"
        message = row[col_message].strip()
        time_str = row[col_time].strip() if col_time < len(row) else ""
        country = row[col_country].strip() if col_country < len(row) else None
        region_name = row[col_region].strip() if col_region < len(row) else None
        city = row[col_city].strip() if col_city < len(row) else None

        # Calculate derived fields & SHA-256 hash
        ts_utc, hour_of_day, day_of_week, is_business_hours, dedup_hash = compute_derived_fields(
            machine_name, source, entry_type, time_str, message
        )

        # Check duplicate
        if dedup_hash in existing_dedup_hashes:
            duplicates_count += 1
            continue

        existing_dedup_hashes.add(dedup_hash)

        # Machine management
        if machine_name not in existing_machines:
            machine_obj = Machine(
                name=machine_name,
                criticality="HIGH" if "admin" in machine_name.lower() or "server" in machine_name.lower() else "MEDIUM",
                first_seen=ts_utc,
                last_seen=ts_utc,
                event_count=0
            )
            db.add(machine_obj)
            db.flush()
            existing_machines[machine_name] = machine_obj

        machine_obj = existing_machines[machine_name]
        m_first = _ensure_utc(machine_obj.first_seen)
        m_last = _ensure_utc(machine_obj.last_seen)
        machine_obj.first_seen = min(m_first, ts_utc)
        machine_obj.last_seen = max(m_last, ts_utc)
        machine_obj.event_count += 1

        # Template management
        tmpl_text, tmpl_hash, param_count = extract_template(message)
        if tmpl_hash not in existing_templates:
            tmpl_obj = MessageTemplate(
                template_hash=tmpl_hash,
                template_text=tmpl_text,
                param_count=param_count,
                first_seen=ts_utc,
                last_seen=ts_utc,
                occurrence_count=1
            )
            db.add(tmpl_obj)
            db.flush()
            existing_templates[tmpl_hash] = tmpl_obj
            templates_created_count += 1
        else:
            tmpl_obj = existing_templates[tmpl_hash]
            t_first = _ensure_utc(tmpl_obj.first_seen)
            t_last = _ensure_utc(tmpl_obj.last_seen)
            tmpl_obj.first_seen = min(t_first, ts_utc)
            tmpl_obj.last_seen = max(t_last, ts_utc)
            tmpl_obj.occurrence_count += 1

        # Entity extraction
        extracted_entities = extract_entities(message)

        event_dict = {
            "machine_id": machine_obj.id,
            "source": source,
            "category": category,
            "entry_type": entry_type,
            "message": message,
            "template_id": tmpl_obj.id,
            "ts_utc": ts_utc,
            "hour_of_day": hour_of_day,
            "day_of_week": day_of_week,
            "is_business_hours": is_business_hours,
            "country": country,
            "region_name": region_name,
            "city": city,
            "extracted_entities": extracted_entities,
            "dedup_hash": dedup_hash,
            "ingested_at": datetime.datetime.now(datetime.UTC)
        }
        pending_events.append(event_dict)
        new_events_count += 1

        if len(pending_events) >= chunk_size:
            db.bulk_insert_mappings(Event, pending_events)
            db.commit()
            pending_events.clear()

    if pending_events:
        db.bulk_insert_mappings(Event, pending_events)
        db.commit()
        pending_events.clear()

    db.commit()

    logger.info(
        f"Ingestion finished. Processed: {total_processed}, New: {new_events_count}, "
        f"Duplicates: {duplicates_count}, Templates: {templates_created_count}"
    )

    return {
        "total_processed": total_processed,
        "new_events": new_events_count,
        "duplicates_skipped": duplicates_count,
        "templates_created": templates_created_count,
        "message": f"Successfully ingested {new_events_count} events from CSV."
    }
