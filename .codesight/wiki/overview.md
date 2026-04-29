# mergen — Overview

> **Navigation aid.** This article shows WHERE things live (routes, models, files). Read actual source files before implementing new features or making changes.

**mergen** is a mixed project built with swiftui, go-net-http, organized as a monorepo.

**Workspaces:** `mergen-cli` (`mergen-cli`), `mergen.xcodeproj` (`mergen.xcodeproj`)

## Scale

24 UI components · 7 library files

**UI:** 24 components (unknown) — see [ui.md](./ui.md)

## High-Impact Files

Changes to these files have the widest blast radius across the codebase:

- `os/exec` — imported by **3** files
- `unicode/utf8` — imported by **1** files
- `encoding/json` — imported by **1** files

---
_Back to [index.md](./index.md) · Generated 2026-04-29_