//
//  FileHelpers.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class FileHelpers {
    static func scanResultsToHTML(scanResults: [Vulnerability]) -> String {
        var html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Scan Results</title>
            <style>
                table {
                    border-collapse: collapse;
                    width: 100%;
                }
                th, td {
                    border: 1px solid black;
                    padding: 8px;
                    text-align: left;
                }
                th {
                    background-color: #f2f2f2;
                }
            </style>
        </head>
        <body>
            <h1>Scan Results</h1>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Category</th>
                    <th>Remediation</th>
                    <th>Severity</th>
                    <th>Documentation</th>
                    <th>Status</th>
                    <th>Mitigation</th>
                    <th>Check Status</th>
                </tr>
        """

        for vulnerability in scanResults {
            html += """
                <tr>
                    <td>\(vulnerability.name)</td>
                    <td>\(vulnerability.description)</td>
                    <td>\(vulnerability.category)</td>
                    <td>\(vulnerability.remediation)</td>
                    <td>\(vulnerability.severity)</td>
                    <td>\(vulnerability.documentation ?? "N/A")</td>
                    <td>\(vulnerability.status ?? "N/A")</td>
                    <td>\(vulnerability.mitigation)</td>
                    <td>\(vulnerability.checkstatus ?? "N/A")</td>
                </tr>
            """
        }

        html += """
            </table>
        </body>
        </html>
        """

        return html
    }
}
