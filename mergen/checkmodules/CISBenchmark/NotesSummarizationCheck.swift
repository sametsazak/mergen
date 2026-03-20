//
//  NotesSummarizationCheck.swift
//  mergen
//
//  CIS 2.5.1.4 - Ensure Notes Summarization Is Disabled

import Foundation

class NotesSummarizationCheck: Vulnerability {
    init() {
        super.init(
            name: "Apple Intelligence Notes Summarization Disabled",
            description: "Apple Intelligence Notes summarization condenses written notes and audio recordings. For environments with sensitive notes or meeting recordings, this should be disabled.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.applicationaccess and set allowNotesTranscription and allowNotesTranscriptionSummary to false.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.5.1.4",
            mitigation: "Disabling Notes summarization ensures audio recordings and notes are not processed externally.",
            checkstatus: "",
            docID: 104,
            cisID: "2.5.1.4"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowNotesTranscription').js"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "false" {
                status = "Notes Summarization is disabled."
                checkstatus = "Green"
            } else if output == "true" {
                status = "Notes Summarization is enabled."
                checkstatus = "Red"
            } else {
                status = "No MDM profile found. Notes Summarization state unknown."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Apple Intelligence Notes Summarization"
        }
    }
}
