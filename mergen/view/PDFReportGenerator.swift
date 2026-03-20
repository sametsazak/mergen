//
//  PDFReportGenerator.swift
//  mergen
//
//  Renders the HTML report in an off-screen WKWebView and exports
//  it as a PDF via WebKit's native createPDF API (macOS 11+).
//

import WebKit
import AppKit

@MainActor
final class PDFReportGenerator: NSObject, WKNavigationDelegate {

    // Keep alive until async work is done
    private static var live: [PDFReportGenerator] = []

    private var webView: WKWebView?
    private var panel:   NSPanel?
    private var onDone:  ((Result<Data, Error>) -> Void)?

    // MARK: - Public entry point

    static func export(
        html: String,
        completion: @escaping @MainActor (Result<Data, Error>) -> Void
    ) {
        let gen = PDFReportGenerator()
        live.append(gen)
        gen.start(html: html) { result in
            completion(result)
            live.removeAll { $0 === gen }
        }
    }

    // MARK: - Private

    private func start(html: String, completion: @escaping (Result<Data, Error>) -> Void) {
        onDone = completion

        // A4 at 96 dpi ≈ 794 × 1123 pt
        let size  = CGSize(width: 850, height: 1100)
        let frame = CGRect(origin: .zero, size: size)

        // Off-screen panel — positioned far off display
        let offRect = CGRect(x: -10_000, y: -10_000, width: size.width, height: size.height)
        let p = NSPanel(
            contentRect: offRect,
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        p.isReleasedWhenClosed = false
        p.backgroundColor = .clear
        panel = p

        let wv = WKWebView(frame: frame)
        wv.navigationDelegate = self
        p.contentView = wv
        webView = wv

        // Must be in window hierarchy for WebKit to render
        p.orderFrontRegardless()
        wv.loadHTMLString(html, baseURL: nil)
    }

    // MARK: - WKNavigationDelegate

    nonisolated func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        Task { @MainActor in
            guard let wv = self.webView else { return }

            let config = WKPDFConfiguration()
            config.rect = CGRect(origin: .zero, size: CGSize(width: 850, height: 1100))

            wv.createPDF(configuration: config) { [weak self] result in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    self.onDone?(result.mapError { $0 as Error })
                    self.teardown()
                }
            }
        }
    }

    nonisolated func webView(_ webView: WKWebView,
                             didFail navigation: WKNavigation!,
                             withError error: Error) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            self.onDone?(.failure(error))
            self.teardown()
        }
    }

    nonisolated func webView(_ webView: WKWebView,
                             didFailProvisionalNavigation navigation: WKNavigation!,
                             withError error: Error) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            self.onDone?(.failure(error))
            self.teardown()
        }
    }

    // MARK: - Cleanup

    private func teardown() {
        panel?.close()
        panel  = nil
        webView = nil
    }
}
