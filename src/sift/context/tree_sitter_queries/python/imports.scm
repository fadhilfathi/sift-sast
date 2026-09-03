; Import statements, both forms. Captured whole; the builder derives the
; module name and any alias from the node text rather than the query,
; because `import a.b.c as d` and `from a.b import c, d as e` need different
; extraction logic per form and a single capture name here would blur which
; form produced it.

(import_statement) @import
(import_from_statement) @import
