"""Browser-safe deterministic BULL policy runtime.

This package is loaded by Pyodide in the static Playground. It intentionally
contains no host execution, filesystem, network, broker, namespace, or secret
access. It only evaluates structured policy requests and produces explainable
decision/audit objects.
"""

from .lab_api import evaluate_json, evaluate_request

__all__ = ["evaluate_json", "evaluate_request"]
