# Investigator interface

## 1. Purpose

The terminal interface configures and follows a case run. Offline HTML pages
make its evidence and limits readable to people who did not operate the tool.
The case directory is the source of truth; neither view hides failed sources.

## 2. Audience and tasks

- An operator chooses the output, collection categories, extra logs, and capture duration.
- An investigator checks findings, the timeline, and the raw source behind each item.
- A reviewer opens the offline report without a running server.

## 3. Visual direction

Use a restrained operations surface: dark ink, slate panels, cyan for active
work, amber for gaps, and red for failed collection. The case status is the
first visual anchor. Color never carries status alone; every state has text.

## 4. Tokens

| Role | Value |
| --- | --- |
| page | `#101923` |
| panel | `#172633` |
| panel raised | `#1d3141` |
| border | `#355061` |
| text | `#e9f1f5` |
| muted | `#a7bcc8` |
| active | `#59d5d0` |
| warning | `#f1bd68` |
| failure | `#f07878` |
| type | system sans for prose, system monospace for evidence |
| spacing | multiples of 4 px |

## 5. Primitives and states

- TUI section row: idle, focused, selected, unavailable.
- TUI setting row: label, current value, short help.
- TUI run row: pending, running, collected, empty, failed, skipped.
- Web status badge: same named states, always with text.
- Web evidence table: sortable by time in source order, readable without scripts.
- Web source link: relative path back to raw or normalized evidence.

## 6. Layout and navigation

The TUI has a guided configuration screen, a review action, and a run view.
Keyboard navigation uses arrows, Space, Enter, and Escape; a narrow terminal
keeps one column. The dashboard has a shared header and links for Overview,
Exfiltration, Timeline, Downloads, and Coverage. Pages scroll normally and
tables can scroll horizontally on small screens.

## 7. Accessibility and safety

Use semantic HTML headings, tables, nav, and visible focus states. Keep the
dashboard useful without JavaScript or network access. Escape all collected
text before it reaches HTML. Distinguish observed evidence from inference and
show unparsed or unavailable sources near findings.

## 8. Accepted limits

No endpoint run can reconstruct events that were never logged. A displayed
historical range means the range of available evidence, not the lifetime of an
application. Imported logs retain their own provenance and time zone context.
