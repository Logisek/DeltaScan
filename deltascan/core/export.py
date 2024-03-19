import csv
from deltascan.core.exceptions import DScanExporterSchemaException
from deltascan.core.schemas import ExportScan
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, Paragraph, TableStyle
from reportlab.lib.units import mm
from marshmallow  import ValidationError

import logging 

logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

class Exporter:
    def __init__(self, data):
        """
        Initializes a new instance of the Exporter class.
        
        Args:
            data (list): The data to be exported.
            
        Raises:
            DScanExporterSchemaException: If there is an error in the data schema.
        """
        try:
            self.data = ExportScan(many=True).load(data)
        except (KeyError, ValidationError) as e:
            logger.error(f"{str(e)}")
            raise DScanExporterSchemaException(f"{str(e)}")

    def to_csv(self, filename):
        """
        Export the data to a CSV file.

        Args:
            filename (str): The name of the CSV file to be created.

        """
        field_names = list(self.data[0].keys())
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=field_names)
            writer.writeheader()
            for row in self.data:
                writer.writerow(row)

    def to_pdf(self, diff_results):
        try:
            doc = SimpleDocTemplate("report.pdf", pagesize=A4)
            style = TableStyle()
            style.add("VALIGN", (0, 0), (-1, -1), "MIDDLE")

            elements = []
            # Add title to the report
            elements.append(Paragraph("Differential Scan Report"))
            elements.append(Paragraph(f'Nmap arguments: {self.data[0]["arguments"]}'))
            elements.append(Paragraph("Diff results"))

            report_schema = [
                ["IP", "OS", "Field", "Values", "Changed", "From", "To"],
            ]

            for diff in diff_results:
                elements.append(Paragraph(f'Differences between: {diff["dates"][0]} and {diff["dates"][1]}'))
                for field_type,outer_diffs in diff["diffs"]["changed"].items():
                    for field_value, inner_diffs in outer_diffs["changed"].items():
                        for key_diff , value_diff in inner_diffs["changed"].items():
                            report_schema.append(
                                [
                                    self.data[0]["host"],
                                    self.data[0]["results"]["os"],
                                    field_type,
                                    field_value,
                                    key_diff,
                                    value_diff["from"],
                                    value_diff["to"]
                                ]
                            )
            table = Table(report_schema)
            table.setStyle(style)
            elements.append(table)
            doc.build(elements)

        except Exception as e:
            print("Error generating PDF report: " + str(e))
            return
