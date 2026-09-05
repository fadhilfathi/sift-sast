"""Eval snapshot: xss template. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import jinja2
import jinja2
ENV = jinja2.Environment(autoescape=True)


def alpha_render(name):
    template = ENV.from_string("Hello {{ who }}")
    return template.render(who=name)

def beta_render(body):
    template = ENV.from_string(body)
    return template.render()
