---
name: csv-tool
description: Summarize CSV files.
---
Read the CSV file the user names. Detect the delimiter and the header row. For each column report its name, its type, the number of empty cells, and the minimum and maximum for numeric columns. Keep the summary under twenty lines, never print more than five sample rows, and ask before reading a file larger than fifty megabytes. When the file has more than forty columns, group them by type first and summarize each group. If the user wants more detail, follow the steps in WORKFLOW.md.
