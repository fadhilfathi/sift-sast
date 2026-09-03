; Function definitions, with and without decorators.
;
; Both patterns match a decorated function's inner function_definition node —
; pattern 0 additionally via the decorated_definition wrapper, pattern 1 via
; the bare function_definition inside it. The builder dedupes by node identity
; and keeps the decorated match, which is the only one carrying @deco.
;
; Nested and async functions are not special-cased: `async def` still parses
; as a function_definition in this grammar, and a function nested inside
; another matches this query too. The builder chooses "smallest enclosing
; span" rather than "first match", so nesting resolves correctly without a
; separate query.

(decorated_definition
  (decorator)+ @deco
  definition: (function_definition
    name: (identifier) @name
    parameters: (parameters) @params
    body: (block) @body) @def) @decorated

(function_definition
  name: (identifier) @name
  parameters: (parameters) @params
  body: (block) @body) @def
