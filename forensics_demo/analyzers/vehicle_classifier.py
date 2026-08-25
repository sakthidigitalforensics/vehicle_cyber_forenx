"""
Schema-aware classification for vehicle telematics / fleet-tracking exports
(GPS ping logs, OBD-II diagnostic session logs, odometer + ignition event
logs - the kind of CSV export a fleet-management or telematics-control-unit
(TCU) platform produces).

Same approach as analyzers/m365_classifier.py: detect the schema from the
header row and map known columns directly onto Event fields, rather than
running the row through the generic keyword classifier. Falls back to
returning None for any row that doesn't match the schema, so unrelated
CSVs are unaffected.
"""

from core.timeparse import extract_timestamp


def _norm(key):
    return str(key).strip().lower().replace(" ", "").replace("_", "").replace("-", "")


def _get(row, *names):
    """Case/space/underscore-insensitive column lookup."""
    normed = {_norm(k): v for k, v in row.items()}
    for name in names:
        v = normed.get(_norm(name))
        if v not in (None, ""):
            return v
    return None


def detect_schema(row):
    keys = {_norm(k) for k in row.keys()}
    if "vin" in keys and (keys & {"odometerkm", "ignitionstate", "eventtype", "geofencezone", "dtccode"}):
        return "vehicle_telematics"
    return None


def _base_event(timestamp, approximate, category, actor, action, outcome=None, objects=None, raw=""):
    return dict(timestamp=timestamp.isoformat() if timestamp else None, approximate=approximate,
                category=category, actor=actor, action=action, outcome=outcome,
                source_ip=None, dest_ip=None, port=None, protocol=None,
                objects=objects or [], raw=raw)


# Technician IDs recognised as legitimate fleet-maintenance staff for this
# case's demo data. Anything else opening an OBD-II session is flagged by
# unauthorized_obd_access_detector in analyzers/pattern_detectors.py.
AUTHORIZED_TECHNICIAN_IDS = {"AUTH-TECH-01", "AUTH-TECH-02"}


def classify_vehicle_row(row, fallback_date=None):
    ts_raw = _get(row, "timestamp", "time", "date")
    timestamp, approx = extract_timestamp(str(ts_raw), fallback_date) if ts_raw else (None, True)

    vin = _get(row, "vin")
    event_type = str(_get(row, "eventtype", "event_type", "event") or "").upper()
    lat = _get(row, "latitude", "lat")
    lon = _get(row, "longitude", "lon", "lng")
    speed = _get(row, "speedkmh", "speed_kmh", "speed")
    odometer = _get(row, "odometerkm", "odometer_km", "odometer")
    ignition = _get(row, "ignitionstate", "ignition_state", "ignition")
    key_fob = _get(row, "keyfobid", "key_fob_id", "keyfob")
    technician = _get(row, "technicianid", "technician_id")
    geofence = _get(row, "geofencezone", "geofence_zone")
    dtc = _get(row, "dtccode", "dtc_code", "dtc")
    location_label = _get(row, "locationlabel", "location_label", "location")

    objects = [f"VIN:{vin}"] if vin else []
    if lat and lon:
        objects.append(f"GPSLat:{lat}")
        objects.append(f"GPSLon:{lon}")
    if odometer:
        objects.append(f"Odometer:{odometer}")
    if speed:
        objects.append(f"Speed:{speed}")
    if key_fob:
        objects.append(f"KeyFobID:{key_fob}")
    if technician:
        objects.append(f"TechnicianID:{technician}")
    if geofence:
        objects.append(f"GeofenceZone:{geofence}")
    if dtc:
        objects.append(f"DTC:{dtc}")
    if location_label:
        objects.append(f"LocationLabel:{location_label}")

    outcome = None
    action = event_type.replace("_", " ").lower() or "vehicle telematics event"

    if event_type in ("IGNITION_ON", "IGNITION_OFF"):
        action = "ignition on" if event_type == "IGNITION_ON" else "ignition off"
        no_fob = not key_fob or str(key_fob).strip().upper() in ("NONE", "UNAUTHORIZED", "")
        if event_type == "IGNITION_ON" and no_fob:
            action = "ignition ON without a recognized key fob (immobilizer bypass suspected)"
            outcome = "Anomaly"
    elif event_type in ("GPS_PING", "GPS_FIX"):
        action = "GPS position report"
    elif event_type == "OBD_DIAGNOSTIC":
        action = "OBD-II diagnostic session opened"
        if technician and str(technician).upper() not in AUTHORIZED_TECHNICIAN_IDS:
            outcome = "Anomaly"
    elif event_type == "ODOMETER_READING":
        action = "odometer reading logged"
    elif event_type == "GEOFENCE_BREACH":
        action = "geofence breach"
        outcome = "Breach"
    elif event_type == "DTC_SET":
        action = f"diagnostic trouble code set" + (f" ({dtc})" if dtc else "")
        outcome = "Anomaly"
    elif event_type == "DTC_CLEARED":
        action = f"diagnostic trouble code cleared" + (f" ({dtc})" if dtc else "")
    elif event_type == "HARSH_BRAKING":
        action = "harsh braking event"
    elif event_type == "OVERSPEED":
        action = "overspeed event"
        outcome = "Anomaly"

    raw = f"[Vehicle telematics] VIN {vin}: {action}" + (f" @ {lat},{lon}" if lat and lon else "")
    return _base_event(timestamp, approx, "Vehicle Telematics", vin, action, outcome, objects=objects, raw=raw)


CLASSIFIERS = {
    "vehicle_telematics": classify_vehicle_row,
}

SCHEMA_LABELS = {
    "vehicle_telematics": "Vehicle Telematics / GPS-OBD-II Export",
}


def try_classify(row_data, fallback_date=None):
    """Returns an Event field dict if row_data matches the vehicle telematics schema, else None."""
    if not row_data:
        return None
    schema = detect_schema(row_data)
    if not schema:
        return None
    event = CLASSIFIERS[schema](row_data, fallback_date)
    event["schema"] = schema
    return event
