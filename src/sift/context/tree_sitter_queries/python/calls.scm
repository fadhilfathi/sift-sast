; Call expressions, named by the identifier or attribute being called.
;
; This one query serves two purposes in the builder: applied within a
; function's body it finds callees (D6: a name matching DYNAMIC_CALL_NAMES —
; getattr, eval, exec, and friends — is how dynamic-dispatch is detected);
; applied across a project's files filtered to a target name it finds callers.
;
; A call whose target is neither a bare name nor a simple attribute — calling
; the result of another call, calling through a subscript, calling a
; computed expression — matches nothing here. That is deliberate: inventing a
; name for a callee we cannot statically identify would be a guess, and the
; absence shows up as a call the builder cannot resolve rather than a wrong one.

(call
  function: [
    (identifier) @name
    (attribute attribute: (identifier) @name)
  ]
  arguments: (argument_list) @args) @call
