import math

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.models import Baseline, Event


def compute_machine_baselines(db: Session) -> int:
    """
    Computes statistical profiles (hourly/daily event volume mean & stddev) for each machine & source.
    Stores/updates results in `baselines` table.
    """
    # Group events by machine_id, source
    query = (
        select(
            Event.machine_id,
            Event.source,
            func.count(Event.id).label("total_count"),
            func.min(Event.ts_utc).label("min_ts"),
            func.max(Event.ts_utc).label("max_ts")
        )
        .group_by(Event.machine_id, Event.source)
    )

    results = db.execute(query).all()
    count_updated = 0

    for row in results:
        machine_id = row.machine_id
        source = row.source
        total_count = row.total_count
        min_ts = row.min_ts
        max_ts = row.max_ts

        if not min_ts or not max_ts:
            continue

        # Calculate time span in hours (minimum 1 hour)
        hours_diff = max(1.0, (max_ts - min_ts).total_seconds() / 3600.0)
        mean_hourly = total_count / hours_diff
        
        # Simplified standard deviation calculation based on Poisson/binomial variance assumption
        stddev_hourly = math.sqrt(mean_hourly)

        # Upsert baseline
        baseline = db.get(Baseline, (machine_id, source, "hourly_volume"))
        if not baseline:
            baseline = Baseline(
                machine_id=machine_id,
                source=source,
                metric="hourly_volume",
                window_start=min_ts,
                window_end=max_ts,
                mean=mean_hourly,
                stddev=stddev_hourly,
                sample_count=int(hours_diff)
            )
            db.add(baseline)
        else:
            baseline.window_start = min_ts
            baseline.window_end = max_ts
            baseline.mean = mean_hourly
            baseline.stddev = stddev_hourly
            baseline.sample_count = int(hours_diff)

        count_updated += 1

    db.commit()
    return count_updated
