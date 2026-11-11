
import csv
import json
from collections import Counter
from datetime import datetime

import database


def split_timestamp(timestamp):
    """Separate a full timestamp into date and time."""
    if not timestamp:
        return "N/A", "N/A"

    try:
        dt = datetime.fromisoformat(str(timestamp))
        return (
            dt.strftime("%Y-%m-%d"),
            dt.strftime("%H:%M:%S")
        )
    except ValueError:
        # Preserve the original value if it has an unexpected format.
        parts = str(timestamp).split(" ", 1)

        if len(parts) == 2:
            return parts[0], parts[1]

        return parts[0], "N/A"


def get_packet_data():
    """Retrieve packet records from the SQLite database."""
    rows = database.get_all_packets()
    packets = []

    for row in rows:
        timestamp, source, destination, protocol, length, info = row

        date, time = split_timestamp(timestamp)

        packets.append({
            "date": date,
            "time": time,
            "timestamp": timestamp or "",
            "protocol": protocol or "N/A",
            "source": source or "N/A",
            "destination": destination or "N/A",
            "length": length or 0,
            "info": info or ""
        })

    return packets


def export_csv(file_path):
    """Export packet logs to CSV."""
    packets = get_packet_data()

    if not packets:
        raise ValueError("There are no packet records to export.")

    fieldnames = [
        "date",
        "time",
        "protocol",
        "source",
        "destination",
        "length",
        "info"
    ]

    with open(file_path, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(packets)


def export_json(file_path):
    """Export packet logs to JSON."""
    packets = get_packet_data()

    if not packets:
        raise ValueError("There are no packet records to export.")

    report = {
        "report_generated": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "total_packets": len(packets),
        "total_bytes": sum(
            int(packet["length"] or 0) for packet in packets
        ),
        "protocol_statistics": dict(
            Counter(packet["protocol"] for packet in packets)
        ),
        "packets": packets
    }

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)


def export_pdf(file_path):
    """Export packet logs and traffic statistics to PDF."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import landscape, A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle
        )
    except ImportError:
        raise ImportError(
            "PDF export requires ReportLab. Install it using:\n"
            "python -m pip install reportlab"
        )

    packets = get_packet_data()

    if not packets:
        raise ValueError("There are no packet records to export.")

    total_packets = len(packets)
    total_bytes = sum(
        int(packet["length"] or 0) for packet in packets
    )

    protocol_counts = Counter(
        packet["protocol"] for packet in packets
    )

    styles = getSampleStyleSheet()

    document = SimpleDocTemplate(
        file_path,
        pagesize=landscape(A4),
        rightMargin=10 * mm,
        leftMargin=10 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm
    )

    elements = []

    # Report title
    elements.append(
        Paragraph(
            "LAN Network Traffic Analyzer Report",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 10))

    elements.append(
        Paragraph(
            f"Report Generated: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 15))

    # Traffic summary
    elements.append(
        Paragraph("Traffic Summary", styles["Heading2"])
    )

    summary_data = [
        ["Metric", "Value"],
        ["Total Packets", str(total_packets)],
        ["Total Data", f"{total_bytes:,} bytes"]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[100 * mm, 70 * mm]
    )

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightblue),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    # Protocol statistics
    elements.append(
        Paragraph("Protocol Statistics", styles["Heading2"])
    )

    protocol_data = [["Protocol", "Packet Count"]]

    for protocol, count in protocol_counts.most_common():
        protocol_data.append([str(protocol), str(count)])

    protocol_table = Table(
        protocol_data,
        repeatRows=1
    )

    protocol_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightblue),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6)
    ]))

    elements.append(protocol_table)
    elements.append(Spacer(1, 15))

    # Packet logs
    elements.append(
        Paragraph("Packet Logs", styles["Heading2"])
    )

    table_data = [[
        "Date",
        "Time",
        "Protocol",
        "Source",
        "Destination",
        "Length",
        "Info"
    ]]

    for packet in packets:
        table_data.append([
            str(packet["date"]),
            str(packet["time"]),
            str(packet["protocol"]),
            str(packet["source"]),
            str(packet["destination"]),
            str(packet["length"]),
            str(packet["info"])
        ])

    packet_table = Table(
        table_data,
        repeatRows=1,
        colWidths=[
            22 * mm,
            20 * mm,
            20 * mm,
            35 * mm,
            35 * mm,
            15 * mm,
            120 * mm
        ]
    )

    packet_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightblue),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")
    ]))

    elements.append(packet_table)

    document.build(elements)


def export_packets(file_path, file_type):
    """Choose the requested export format."""
    file_type = file_type.lower().strip()

    if file_type == "csv":
        export_csv(file_path)

    elif file_type == "json":
        export_json(file_path)

    elif file_type == "pdf":
        export_pdf(file_path)

    else:
        raise ValueError(
            "Unsupported export format. Choose CSV, JSON, or PDF."
        )
