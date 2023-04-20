//
//  HTMLReportGenerator.swift
//  mergen
//
//  Created by Samet Sazak on 7.04.2023.
//

import Foundation
import SwiftUI
import Quartz

struct HTMLReportGenerator {
    
    let scanResults: [Vulnerability]
    
    init(scanResults: [Vulnerability]) {
        self.scanResults = scanResults
    }
    
    func generateHTMLReport() -> String {
        var html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Mergen - Scan Results</title>
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js"></script>
            <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/github-fork-ribbon-css/0.2.3/gh-fork-ribbon.min.css" />
        </head>

        <style>

            body {
                background-image: linear-gradient(to right top, #678fc4, #648bbf, #6186bb, #5f82b6, #5c7eb2, #587aae, #5575aa, #5171a6, #4a6ba1, #44669c, #3d6098, #365b93);
                font-family: Arial, sans-serif;
                color:white;
            }
            h1 {
                text-align: center;
                margin-bottom: 30px;
                color:white;
            }
            .container {
                max-width: 80%;
                margin: auto;
                color: #ffffff;
            }
            table {
                background-image: linear-gradient(to right top, #678fc4, #648bbf, #6186bb, #5f82b6, #5c7eb2, #587aae, #5575aa, #5171a6, #4a6ba1, #44669c, #3d6098, #365b93);
                border-collapse: collapse;
                width: 100%;
                color: #ffffff;
            }
            th, td {
                border: 1px solid #dee2e6;
                padding: 8px;
                text-align: left;
                color: #ffffff;
            }
            th {
                font-weight: 600;
                color: #ffffff;
            }
        </style>

        <body>
        <a class="github-fork-ribbon" href="https://url.to-your.repo" data-ribbon="Fork me on GitHub" title="Fork me on GitHub">Fork me on GitHub</a>
        <h1 style="text-align: center;">Mergen - Result Report</h1>
        <br>
        <h6 style="text-align: center;">These checks will provide a comprehensive overview of a macOS system's security settings and configurations. Analyzing and improving these settings will help you enhance the system's security posture and protect it from potential threats.</h6>
        <p></p>
            <div class="container">
                <table class="table table-striped table-dark">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Description</th>
                            <th>Category</th>
                            <th>Remediation</th>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Check Status</th>
                        </tr>
                    </thead>
                    <tbody>
        """

        for vulnerability in scanResults {
            let severityIcon: String
            switch vulnerability.severity {
            case "Low":
                severityIcon = "fas fa-arrow-down text-success"
            case "Medium":
                severityIcon = "fas fa-arrow-right text-warning"
            case "High":
                severityIcon = "fas fa-arrow-up text-danger"
            default:
                severityIcon = "fas fa-question text-secondary"
            }

            let checkStatusIcon: String
            let checkStatusColor: String
            switch vulnerability.checkstatus {
            case "Green":
                checkStatusIcon = "fas fa-check-circle"
                checkStatusColor = "text-success"
            case "Yellow":
                checkStatusIcon = "fas fa-exclamation-circle"
                checkStatusColor = "text-warning"
            case "Red":
                checkStatusIcon = "fas fa-times-circle"
                checkStatusColor = "text-danger"
            default:
                checkStatusIcon = "fas fa-question-circle"
                checkStatusColor = "text-secondary"
            }

            html += """
                <tr>
                    <td>\(vulnerability.name)</td>
                    <td>\(vulnerability.description)</td>
                    <td>\(vulnerability.category)</td>
                    <td>\(vulnerability.remediation)</td>
                    <td><i class="\(severityIcon)"></i> \(vulnerability.severity)</td>
                    <td>\(vulnerability.status ?? "N/A")</td>
                    <td><i class="\(checkStatusIcon) \(checkStatusColor)"></i></td>
            </tr>
        """
    }

    html += """
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """

        return html
    
    }
}

struct FileUtils {
    static func saveHTMLStringToFile(_ htmlString: String) {
        let savePanel = NSSavePanel()
        savePanel.nameFieldStringValue = "MergenResult.html"
        savePanel.allowedContentTypes = [UTType.html]

        if savePanel.runModal() == .OK, let url = savePanel.url {
            do {
                try htmlString.write(to: url, atomically: true, encoding: .utf8)
                print("HTML file saved to \(url)")
            } catch {
                print("Error saving HTML file: \(error)")
            }
        }
    }
}
