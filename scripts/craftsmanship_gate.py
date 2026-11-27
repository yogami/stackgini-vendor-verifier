"""Deterministic AST gate enforcing Uncle Bob, Fowler, and Kerievsky rules."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import io
from pathlib import Path
import sys
import tokenize

MAX_CC = 3
MAX_SRC_FUNC_LINES = 30
MAX_TEST_FUNC_LINES = 100
MAX_CLASS_LINES = 1000
MAX_PORT_METHODS = 3
MAX_PARAMS = 4
MAX_LINE_LENGTH = 120
DEPRECATED_LOOKBACK = 4
ALLOWED_NUMBERS = frozenset({-1, 0, 1, 2, 100, 0.0, 1.0})

REQUIRED_DDD_DIRS = ("domain", "ports", "application", "infrastructure")
LAYER_BANS: dict[str, frozenset[str]] = {
    "domain": frozenset({"ports", "application", "infrastructure", "api", "entrypoints"}),
    "ports": frozenset({"application", "infrastructure", "api", "entrypoints"}),
    "application": frozenset({"infrastructure", "api", "entrypoints"}),
    "infrastructure": frozenset({"api", "entrypoints"}),
}
IO_BOUND_LAYERS = frozenset({"domain", "ports", "application"})
STRICT_TYPE_LAYERS = frozenset({"domain", "ports"})
MAGIC_FREE_LAYERS = frozenset({"domain", "application"})
FLAG_FREE_LAYERS = frozenset({"domain", "ports", "application"})

FORBIDDEN_IO_LIBS = frozenset(
    {
        "httpx",
        "playwright",
        "fastapi",
        "starlette",
        "uvicorn",
        "tavily",
        "google",
        "openai",
        "anthropic",
        "whois",
        "dns",
        "subprocess",
        "socket",
        "requests",
        "urllib.request",
    }
)
SUPPRESSION_TOKENS = ("# noqa", "# type: ignore", "# nosec", "# pragma: no cover", "# fmt: skip")
BRANCH_NODES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.ExceptHandler,
    ast.With,
    ast.AsyncWith,
    ast.IfExp,
)
SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
FUNC_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


@dataclass(frozen=True)
class GateConfig:
    """Immutable CLI options for craftsmanship verification."""

    root: Path
    require_ddd_dirs: bool
    require_specs: bool


@dataclass(frozen=True)
class FileContext:
    """Parsed AST and metadata for a single repository Python file."""

    rel: str
    layer: str
    text: str
    lines: tuple[str, ...]
    tree: ast.Module


def _iter_py_files(base: Path) -> list[Path]:
    if not base.exists():
        return []
    return [p for p in sorted(base.rglob("*.py")) if "__pycache__" not in p.parts]


def _parse_risk_token(token: str) -> str:
    cleaned = token.strip(",.;()[]")
    if ":" not in cleaned:
        return ""
    return "" if cleaned.startswith("http") else cleaned


def _load_accepted_risks(root: Path) -> set[str]:
    risks_file = root / "specs" / "ACCEPTED_RISKS.md"
    if not risks_file.exists():
        return set()
    raw_tokens = risks_file.read_text(encoding="utf-8").replace("`", " ").split()
    parsed = [_parse_risk_token(tok) for tok in raw_tokens]
    return {item for item in parsed if item}


def _resolve_layer(src_dir: Path, path: Path) -> str:
    try:
        return path.relative_to(src_dir).parts[0]
    except (ValueError, IndexError):
        return "tests"


def _build_context(root: Path, src_dir: Path, path: Path) -> FileContext:
    rel = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8")
    layer = _resolve_layer(src_dir, path)
    tree = ast.parse(text, filename=rel)
    return FileContext(rel=rel, layer=layer, text=text, lines=tuple(text.splitlines()), tree=tree)


def _seq_branch_delta(node: ast.AST) -> int:
    if isinstance(node, ast.comprehension):
        return len(node.ifs)
    if isinstance(node, ast.Match):
        return len(node.cases)
    return 0


def _node_branch_delta(node: ast.AST) -> int:
    if isinstance(node, BRANCH_NODES):
        return 1
    if isinstance(node, ast.BoolOp):
        return len(node.values) - 1
    return _seq_branch_delta(node)


def _iter_own_scope(root_node: ast.AST) -> list[ast.AST]:
    collected: list[ast.AST] = []
    stack: list[ast.AST] = list(ast.iter_child_nodes(root_node))
    while stack:
        current = stack.pop()
        if not isinstance(current, SCOPE_NODES):
            collected.append(current)
            stack.extend(ast.iter_child_nodes(current))
    return collected


def _compute_cc(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    deltas = [_node_branch_delta(node) for node in _iter_own_scope(func_node)]
    return 1 + sum(deltas)


def _span_lines(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> int:
    end_line = node.end_lineno if node.end_lineno is not None else node.lineno
    return end_line - node.lineno + 1


def _node_contains_line(node: ast.AST, line: int) -> bool:
    if not isinstance(node, SCOPE_NODES):
        return False
    end_line = node.end_lineno if node.end_lineno is not None else node.lineno
    return node.lineno <= line <= end_line


def _matching_scopes(tree: ast.AST, line: int) -> list[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef]:
    return [n for n in ast.walk(tree) if isinstance(n, SCOPE_NODES) and _node_contains_line(n, line)]


def _symbol_at_line(tree: ast.AST, line: int) -> str:
    matches = [n for n in ast.walk(tree) if _node_contains_line(n, line)]
    if not matches:
        return "<module>"
    narrowest = min(matches, key=_span_lines)  # type-checked via SCOPE_NODES guard
    return getattr(narrowest, "name", "<module>")


def _check_line_lengths(ctx: FileContext) -> list[str]:
    return [
        f"{ctx.rel}:{idx} line length {len(line)} > {MAX_LINE_LENGTH}"
        for idx, line in enumerate(ctx.lines, start=1)
        if len(line) > MAX_LINE_LENGTH
    ]


def _comment_suppression_error(ctx: FileContext, tok: tokenize.TokenInfo, accepted: set[str]) -> str:
    low = tok.string.lower()
    if not any(marker in low for marker in SUPPRESSION_TOKENS):
        return ""
    sym = _symbol_at_line(ctx.tree, tok.start[0])
    if f"{ctx.rel}:{sym}" in accepted:
        return ""
    return f"{ctx.rel}:{tok.start[0]} forbidden suppression '{tok.string}' on {sym}"


def _op_semicolon_error(ctx: FileContext, tok: tokenize.TokenInfo) -> str:
    return f"{ctx.rel}:{tok.start[0]} chained ';' forbidden" if tok.string == ";" else ""


def _token_error(ctx: FileContext, tok: tokenize.TokenInfo, accepted: set[str]) -> str:
    if tok.type == tokenize.OP:
        return _op_semicolon_error(ctx, tok)
    if tok.type == tokenize.COMMENT:
        return _comment_suppression_error(ctx, tok, accepted)
    return ""


def _check_tokens(ctx: FileContext, accepted: set[str]) -> list[str]:
    tokens = tokenize.generate_tokens(io.StringIO(ctx.text).readline)
    raw_errors = [_token_error(ctx, tok, accepted) for tok in tokens]
    return [err for err in raw_errors if err]


def _strip_receiver(args: list[ast.arg]) -> list[ast.arg]:
    if not args:
        return args
    return args[1:] if args[0].arg in {"self", "cls"} else args


def _non_self_args(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    combined = [*func_node.args.posonlyargs, *func_node.args.args, *func_node.args.kwonlyargs]
    return _strip_receiver(combined)


def _is_bool_flag_arg(arg: ast.arg) -> bool:
    return False if arg.annotation is None else ast.unparse(arg.annotation) == "bool"


def _is_bool_const(expr: ast.AST | None) -> bool:
    if not isinstance(expr, ast.Constant):
        return False
    return isinstance(expr.value, bool)


def _has_bool_default(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    defaults = [*func_node.args.defaults, *func_node.args.kw_defaults]
    return any(_is_bool_const(d) for d in defaults)


def _has_flag_smell(node: ast.FunctionDef | ast.AsyncFunctionDef, params: list[ast.arg]) -> bool:
    if any(_is_bool_flag_arg(p) for p in params):
        return True
    return _has_bool_default(node)


def _allows_flag_check(ctx: FileContext, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if node.name == "__init__":
        return False
    return ctx.layer in FLAG_FREE_LAYERS


def _flag_smell_errors(
    ctx: FileContext, node: ast.FunctionDef | ast.AsyncFunctionDef, params: list[ast.arg]
) -> list[str]:
    if not _allows_flag_check(ctx, node):
        return []
    if _has_flag_smell(node, params):
        return [f"{ctx.rel}:{node.lineno} boolean flag parameter smell on '{node.name}'"]
    return []


def _param_count_errors(
    ctx: FileContext, node: ast.FunctionDef | ast.AsyncFunctionDef, params: list[ast.arg]
) -> list[str]:
    if len(params) > MAX_PARAMS:
        return [f"{ctx.rel}:{node.lineno} '{node.name}' has {len(params)} params > {MAX_PARAMS}"]
    return []


def _check_signature_smells(ctx: FileContext, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    params = _non_self_args(node)
    return _param_count_errors(ctx, node, params) + _flag_smell_errors(ctx, node, params)


def _check_src_function(ctx: FileContext, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    errors = _check_signature_smells(ctx, node)
    span = _span_lines(node)
    if span > MAX_SRC_FUNC_LINES:
        errors.append(f"{ctx.rel}:{node.lineno} func '{node.name}' length {span} > {MAX_SRC_FUNC_LINES}")
    cc = _compute_cc(node)
    if cc > MAX_CC:
        errors.append(f"{ctx.rel}:{node.lineno} func '{node.name}' CC={cc} > {MAX_CC}")
    return errors


def _is_dataclass_without_frozen(dec: ast.expr) -> bool:
    text = ast.unparse(dec)
    if not text.startswith("dataclass"):
        return False
    return "frozen=True" not in text


def _count_public_methods(cls_node: ast.ClassDef) -> int:
    methods = [n for n in cls_node.body if isinstance(n, FUNC_NODES)]
    return sum(1 for m in methods if not m.name.startswith("_"))


def _frozen_domain_errors(ctx: FileContext, cls_node: ast.ClassDef) -> list[str]:
    if ctx.layer != "domain":
        return []
    if any(_is_dataclass_without_frozen(d) for d in cls_node.decorator_list):
        return [f"{ctx.rel}:{cls_node.lineno} domain dataclass '{cls_node.name}' must set frozen=True"]
    return []


def _isp_port_errors(ctx: FileContext, cls_node: ast.ClassDef) -> list[str]:
    if ctx.layer != "ports":
        return []
    if _count_public_methods(cls_node) > MAX_PORT_METHODS:
        return [f"{ctx.rel}:{cls_node.lineno} port '{cls_node.name}' exceeds ISP limit ({MAX_PORT_METHODS})"]
    return []


def _check_class_rules(ctx: FileContext, cls_node: ast.ClassDef) -> list[str]:
    errors = _frozen_domain_errors(ctx, cls_node) + _isp_port_errors(ctx, cls_node)
    span = _span_lines(cls_node)
    if span >= MAX_CLASS_LINES:
        errors.append(f"{ctx.rel}:{cls_node.lineno} class '{cls_node.name}' length {span} >= {MAX_CLASS_LINES}")
    return errors


def _is_numeric_non_bool(val: object) -> bool:
    if isinstance(val, bool):
        return False
    return isinstance(val, (int, float))


def _is_magic_number(node: ast.AST) -> bool:
    if not isinstance(node, ast.Constant):
        return False
    if not _is_numeric_non_bool(node.value):
        return False
    return node.value not in ALLOWED_NUMBERS


def _check_magic_numbers(ctx: FileContext, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    if ctx.layer not in MAGIC_FREE_LAYERS:
        return []
    offenders = [n for n in _iter_own_scope(func_node) if _is_magic_number(n)]
    return [
        f"{ctx.rel}:{getattr(n, 'lineno', func_node.lineno)} magic number in '{func_node.name}'"
        for n in offenders
    ]


def _is_any_reference(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "Any"
    if isinstance(node, ast.Attribute):
        return node.attr == "Any"
    return False


def _check_primitive_obsession_any(ctx: FileContext) -> list[str]:
    if ctx.layer not in STRICT_TYPE_LAYERS:
        return []
    hits = [n for n in ast.walk(ctx.tree) if _is_any_reference(n)]
    return [f"{ctx.rel}:{getattr(n, 'lineno', 1)} forbidden 'Any' in {ctx.layer} layer" for n in hits]


def _from_import_pairs(node: ast.ImportFrom) -> list[tuple[int, str]]:
    return [(node.lineno, node.module)] if node.module else []


def _node_imports(node: ast.AST) -> list[tuple[int, str]]:
    if isinstance(node, ast.Import):
        return [(node.lineno, alias.name) for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        return _from_import_pairs(node)
    return []


def _extract_imports(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        found.extend(_node_imports(node))
    return found


def _is_forbidden_io_mod(mod: str) -> bool:
    if mod in FORBIDDEN_IO_LIBS:
        return True
    return mod.split(".")[0] in FORBIDDEN_IO_LIBS


def _violates_layer_import(layer: str, mod: str) -> bool:
    if set(mod.split(".")) & LAYER_BANS.get(layer, frozenset()):
        return True
    if layer not in IO_BOUND_LAYERS:
        return False
    return _is_forbidden_io_mod(mod)


def _check_hexagonal_imports(ctx: FileContext) -> list[str]:
    return [
        f"{ctx.rel}:{lineno} {ctx.layer} import violation: '{mod}'"
        for lineno, mod in _extract_imports(ctx.tree)
        if _violates_layer_import(ctx.layer, mod)
    ]


def _check_src_node(ctx: FileContext, node: ast.AST) -> list[str]:
    if isinstance(node, ast.ClassDef):
        return _check_class_rules(ctx, node)
    if isinstance(node, FUNC_NODES):
        return _check_src_function(ctx, node) + _check_magic_numbers(ctx, node)
    return []


def _check_src_file(ctx: FileContext, accepted: set[str]) -> list[str]:
    errors = _check_line_lengths(ctx) + _check_tokens(ctx, accepted)
    errors.extend(_check_hexagonal_imports(ctx))
    errors.extend(_check_primitive_obsession_any(ctx))
    for node in ast.walk(ctx.tree):
        errors.extend(_check_src_node(ctx, node))
    return errors


def _has_deprecated_marker(lines: tuple[str, ...], func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    first_line = min([func_node.lineno, *[d.lineno for d in func_node.decorator_list]])
    window = lines[max(0, first_line - DEPRECATED_LOOKBACK) : first_line]
    return any("# DEPRECATED:" in line for line in window)


def _is_skip_decorator(dec: ast.expr) -> bool:
    text = ast.unparse(dec)
    return any(tok in text for tok in ("pytest.mark.skip", "pytest.mark.xfail", "unittest.skip"))


def _is_self_eq(test: ast.Compare) -> bool:
    if len(test.ops) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    return ast.unparse(test.left) == ast.unparse(test.comparators[0])


def _is_tautological_assert(node: ast.Assert) -> bool:
    if _is_bool_const(node.test):
        return True
    if isinstance(node.test, ast.Compare):
        return _is_self_eq(node.test)
    return False


def _is_weak_not_none_assert(node: ast.Assert) -> bool:
    if isinstance(node.test, ast.Name):
        return True
    return ast.unparse(node.test).endswith(" is not None")


def _tautology_errors(ctx: FileContext, fn_name: str, asserts: list[ast.Assert]) -> list[str]:
    return [
        f"{ctx.rel}:{a.lineno} tautological assert in '{fn_name}'"
        for a in asserts
        if _is_tautological_assert(a)
    ]


def _all_asserts_weak(asserts: list[ast.Assert]) -> bool:
    if not asserts:
        return False
    return all(_is_weak_not_none_assert(a) for a in asserts)


def _weak_sole_assert_errors(
    ctx: FileContext, fn_name: str, asserts: list[ast.Assert], raises: int
) -> list[str]:
    if raises > 0:
        return []
    if _all_asserts_weak(asserts):
        return [f"{ctx.rel}:{asserts[0].lineno} weak sole non-None assert in '{fn_name}'"]
    return []


def _check_assert_quality(
    ctx: FileContext, fn_name: str, asserts: list[ast.Assert], raises: int
) -> list[str]:
    if not asserts and raises == 0:
        return [f"{ctx.rel}:1 empty test '{fn_name}' lacks assert or pytest.raises"]
    return _tautology_errors(ctx, fn_name, asserts) + _weak_sole_assert_errors(ctx, fn_name, asserts, raises)


def _collect_asserts(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Assert]:
    return [n for n in ast.walk(fn) if isinstance(n, ast.Assert)]


def _collect_call_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [ast.unparse(n.func) for n in ast.walk(fn) if isinstance(n, ast.Call)]


def _inline_skip_errors(ctx: FileContext, fn: ast.FunctionDef | ast.AsyncFunctionDef, calls: list[str]) -> list[str]:
    if any(c in {"pytest.skip", "unittest.skip"} for c in calls):
        return [f"{ctx.rel}:{fn.lineno} forbidden inline skip in '{fn.name}'"]
    return []


def _test_body_errors(ctx: FileContext, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    asserts = _collect_asserts(fn)
    calls = _collect_call_names(fn)
    raises = sum(1 for c in calls if c in {"pytest.raises", "raises"})
    return _inline_skip_errors(ctx, fn, calls) + _check_assert_quality(ctx, fn.name, asserts, raises)


def _test_length_errors(ctx: FileContext, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    if _span_lines(fn) >= MAX_TEST_FUNC_LINES:
        return [f"{ctx.rel}:{fn.lineno} test '{fn.name}' length >= {MAX_TEST_FUNC_LINES}"]
    return []


def _skip_decorator_errors(ctx: FileContext, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    if any(_is_skip_decorator(d) for d in fn.decorator_list):
        return [f"{ctx.rel}:{fn.lineno} skip/xfail without '# DEPRECATED:' on '{fn.name}'"]
    return []


def _inspect_test_function(ctx: FileContext, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    errors = _test_length_errors(ctx, fn)
    if _has_deprecated_marker(ctx.lines, fn):
        return errors
    return errors + _skip_decorator_errors(ctx, fn) + _test_body_errors(ctx, fn)


def _test_class_errors(ctx: FileContext, cls_node: ast.ClassDef) -> list[str]:
    if _span_lines(cls_node) >= MAX_CLASS_LINES:
        return [f"{ctx.rel}:{cls_node.lineno} class '{cls_node.name}' length >= {MAX_CLASS_LINES}"]
    return []


def _is_test_func(node: ast.AST) -> bool:
    if not isinstance(node, FUNC_NODES):
        return False
    return node.name.startswith("test_")


def _check_test_node(ctx: FileContext, node: ast.AST) -> list[str]:
    if isinstance(node, ast.ClassDef):
        return _test_class_errors(ctx, node)
    if _is_test_func(node):
        return _inspect_test_function(ctx, node)  # type-narrowed by _is_test_func
    return []


def _check_test_file(ctx: FileContext, accepted: set[str]) -> list[str]:
    errors = _check_line_lengths(ctx) + _check_tokens(ctx, accepted)
    for node in ast.walk(ctx.tree):
        errors.extend(_check_test_node(ctx, node))
    return errors


def _file_has_functions(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return any(isinstance(n, FUNC_NODES) for n in ast.walk(tree))


def _has_functions(files: list[Path]) -> bool:
    return any(_file_has_functions(path) for path in files)


def _check_anemic_domain(src_dir: Path) -> list[str]:
    if not _has_functions(_iter_py_files(src_dir / "application")):
        return []
    if _has_functions(_iter_py_files(src_dir / "domain")):
        return []
    return ["Anemic Domain Model: src/application has logic while src/domain has zero behavior"]


def _ddd_dir_errors(cfg: GateConfig) -> list[str]:
    if not cfg.require_ddd_dirs:
        return []
    src_dir = cfg.root / "src"
    missing = [f"Missing required DDD directory: src/{d}" for d in REQUIRED_DDD_DIRS if not (src_dir / d).is_dir()]
    return missing + _check_anemic_domain(src_dir)


def _spec_dir_errors(cfg: GateConfig) -> list[str]:
    if not cfg.require_specs:
        return []
    return [] if list((cfg.root / "specs").glob("*.spec.md")) else ["Missing living spec files (*.spec.md) in specs/"]


def _check_structure(cfg: GateConfig) -> list[str]:
    return _ddd_dir_errors(cfg) + _spec_dir_errors(cfg)


def run_gate(cfg: GateConfig) -> list[str]:
    """Run all Fowler, Kerievsky, and Uncle Bob checks on cfg.root."""
    errors = _check_structure(cfg)
    accepted = _load_accepted_risks(cfg.root)
    src_dir = cfg.root / "src"
    for path in _iter_py_files(src_dir):
        errors.extend(_check_src_file(_build_context(cfg.root, src_dir, path), accepted))
    for path in _iter_py_files(cfg.root / "tests"):
        errors.extend(_check_test_file(_build_context(cfg.root, src_dir, path), accepted))
    return errors


def _print_outcome(errors: list[str]) -> int:
    if not errors:
        print("CRAFTSMANSHIP_GATE_OK")
        return 0
    for err in errors:
        print(f"FAIL: {err}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments and exit non-zero on any craftsmanship violation."""
    parser = argparse.ArgumentParser(description="Enforce Clean Code, Refactoring, and DDD gates.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--require-ddd-dirs", action="store_true")
    parser.add_argument("--require-specs", action="store_true")
    parsed = parser.parse_args(argv)
    cfg = GateConfig(
        root=parsed.root.resolve(),
        require_ddd_dirs=parsed.require_ddd_dirs,
        require_specs=parsed.require_specs,
    )
    return _print_outcome(run_gate(cfg))


if __name__ == "__main__":
    raise SystemExit(main())
