# Gemini / AI Agent Operational Guardrails (`GEMINI.md`)

This document defines mandatory operational boundaries for AI coding assistants (Gemini / Antigravity) working in this project and any linked Android platform repositories (e.g., `/usr/local/google/home/wkouki/android-26Q2`).

---

## 1. Strict Prohibition of Unsolicited Code Modifications

1. **NEVER Edit Source Code Without Explicit User Instruction**:
   * Do **NOT** modify, patch, or overwrite any source code file (whether in `sdp-file-encrypt` or in the Android platform source tree) unless the user has **explicitly asked** you to implement/modify the code or has **explicitly approved** your proposed change.
   * When the user pastes an email, shares feedback from an external party, or discusses a technical problem, **your default mode MUST be read-only analysis and discussion**.
   * Always present your analysis and proposed changes in the chat response first, and **wait for the user's explicit go-ahead** before calling `replace_file_content`, `multi_replace_file_content`, or `write_to_file` on source files.

2. **Treat Conversational Reflections as Discussion, Not Commands**:
   * Remarks such as *"They replied with this, hmm..."* or *"I guess we might have to build an image..."* are context-sharing and reflection, **NOT** an instruction to immediately start editing platform source code or launching builds.
   * When in doubt about whether the user wants you to execute an action or merely discuss/analyze it, **always ask for confirmation first**.

---

## 2. Strict Prohibition of Unsolicited Builds and Device Operations

1. **No Autonomous Platform Builds or Device Modifications**:
   * Do **NOT** run platform build commands (`m`, `mm`, `ninja`, `lunch`), `adb remount`, `adb push`, `adb install`, or process termination commands without explicit permission from the user.
2. **Read-Only Investigation Only (When Permitted)**:
   * Even during investigation, prefer local static analysis (`grep_search`, `view_file`, `find_by_name`) over heavy shell commands or background tasks.

---

## 3. Terminology and Documentation Rules

1. **Prohibition of the Term "AOSP"**:
   * **NEVER** use the term `"AOSP"` when referring to the Android platform code, source repository, or device builds.
   * Always use approved terms: `"Android platform code"`, `"platform source code"`, `"internal platform repository"`, or `"POC build"`.
2. **Documentation and Comment Language Policy**:
   * All Markdown documentation files (`.md`) and source code comments **MUST be written in English**.
   * Conversational responses in the chat UI should match the user's language (Japanese).
3. **Stream Output Rule**:
   * Never redirect terminal standard output to temporary external files (e.g., `> /tmp/output.txt`). Process outputs directly from the stream.
