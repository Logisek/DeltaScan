from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, Paragraph, TableStyle
from reportlab.lib.units import mm


def generatePdfReport(profile, scanResults):
    try:
        doc = SimpleDocTemplate("report.pdf", pagesize=A4)
        style = TableStyle()
        style.add("VALIGN", (0, 0), (-1, -1), "MIDDLE")

        elements = []

        # Add title to the report
        title = Paragraph("Differential Scan Report for " + profile)
        elements.append(title)

        sectionTitle = Paragraph("Scans performed")
        elements.append(sectionTitle)

        scanList = [
            ["ID", "Profile Name", "Scan Arguments"],
            ["1", "default", "-sV -sC -oA scan"],
            ["2", "default", "-sV -sC -oA scan"],
            ["3", "custom", "-sS -p 80 -oA scan"],
            ["4", "custom", "-sS -p 443 -oA scan"],
            ["5", "custom", "-sS -p 22 -oA scan"],
            ["6", "custom", "-sS -p 8080 -oA scan"],
            ["7", "default", "-sV -sC -oA scan"],
            ["8", "custom", "-sS -p 443 -oA scan"],
        ]

        table = Table(scanList)
        elements.append(table)

        sectionTitle = Paragraph("Scan results")
        elements.append(sectionTitle)

        scanData = [
            ["IP Address", "OS", "Ports", "state"],
        ]

        state = ""
        for host in scanResults:
            if host["state"]:
                state = "up"
            else:
                state = "down"

        for scan in scanResults:
            ports = cleanPorts(scan["ports"])
            scanData.append(
                [
                    scan["host"],
                    scan["os"],
                    ports,
                    state,
                ]
            )

        table = Table(scanData)
        table.setStyle(style)
        elements.append(table)

        sectionTitle = Paragraph("Differences")
        elements.append(sectionTitle)

        differences = [
            # Differential data
            ["Hi :)"],
        ]

        table = Table(differences)
        elements.append(table)

        doc.build(elements)

    except Exception as e:
        print("Error generating PDF report: " + str(e))
        return


def cleanPorts(ports):
    cleanPorts = ""
    for port in ports:
        cleanPorts = (
            str(cleanPorts)
            + str(port.get("port", "na"))
            + "/"
            + str(port.get("service", "na"))
            + "/"
            + str(port.get("product", "na"))
            + "/"
            + str(port.get("state", "na"))
            + "\n"
        )

    return cleanPorts
