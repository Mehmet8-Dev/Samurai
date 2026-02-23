# Project Workflow

## Development Protocol
*   **Test-Driven Development (TDD):** Where feasible, write tests before implementation.
*   **Test Coverage:** Maintain >80% code coverage for critical paths (Python logic).
*   **Reporting:** Instead of atomic git commits, detailed progress reports must be maintained in versioned Markdown files (e.g., `reports/task_X_summary.md` or updated `plan.md`).

## Phase Completion Verification
1.  **Manual Check:** User reviews the generated report/code.
2.  **Test Execution:** Run relevant test suites (`pytest`, `unittest`).
3.  **Report Update:** Mark tasks as completed in the plan and generate a phase summary report.
