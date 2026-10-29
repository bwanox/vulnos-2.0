"""Deterministic, offline AST taint slicer for Python repositories.

Parses a target repository with :mod:`tree_sitter` (primary) or the stdlib
:mod:`ast` (fallback), maps user-controlled entry points (Flask/FastAPI routes,
request parameters, CLI args) to dangerous sinks (``eval``/``exec``,
``subprocess``, SQL string building, ``pickle``, ``open()`` with user paths,
etc.), and emits minimal :class:`~vulnos.core.contracts.CodeSlice` objects —
only the functions/lines on each taint path, small enough for a compact LLM
prompt.

Fully deterministic: files are visited in sorted order, there is no randomness,
no network, and no LLM. Safe to run on a Jetson Orin Nano.
"""

from __future__ import annotations

import ast as _ast
from pathlib import Path
from typing import Iterable

from vulnos.core.contracts import CodeSlice, SinkType

# ---------------------------------------------------------------------------
# tree-sitter (optional; falls back to stdlib ast when unavailable)
# ---------------------------------------------------------------------------

try:  # pragma: no cover - environment dependent
    from tree_sitter import Language, Parser  # type: ignore
    import tree_sitter_python as _tspython  # type: ignore

    _TS_LANGUAGE = Language(_tspython.language())
    _HAS_TREE_SITTER = True
except Exception:  # tree_sitter or its python grammar missing
    _HAS_TREE_SITTER = False


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

# Callable/attribute chains that introduce user-controlled data.
_SOURCE_CALLS = frozenset({
    "request.args.get",
    "request.args.__getitem__",
    "request.form.get",
    "request.form.__getitem__",
    "request.values.get",
    "request.cookies.get",
    "request.headers.get",
    "request.json",
    "sys.argv",
    "os.environ.get",
    "os.environ.__getitem__",
})

# Dangerous sinks. Exact dotted-callee matches take precedence; ".execute" on
# any object is treated as a SQL sink.
_SINK_CALLEES: dict[str, SinkType] = {
    "subprocess.run": SinkType.SUBPROCESS,
    "subprocess.Popen": SinkType.SUBPROCESS,
    "subprocess.call": SinkType.SUBPROCESS,
    "subprocess.check_output": SinkType.SUBPROCESS,
    "subprocess.check_call": SinkType.SUBPROCESS,
    "os.system": SinkType.SUBPROCESS,
    "os.popen": SinkType.SUBPROCESS,
    "eval": SinkType.EVAL_EXEC,
    "exec": SinkType.EVAL_EXEC,
    "pickle.loads": SinkType.PICKLE,
    "pickle.load": SinkType.PICKLE,
    "open": SinkType.FILE_OPEN,
}

# Decorators that mark a function as an entry point (route / CLI handler).
_ROUTE_DECORATORS = frozenset({
    "app.route", "app.get", "app.post", "app.put", "app.delete", "app.patch",
    "router.route", "router.get", "router.post", "router.put",
    "router.delete", "router.patch", "bp.route", "bp.get", "bp.post",
})


# ---------------------------------------------------------------------------
# tree-sitter implementation
# ---------------------------------------------------------------------------

class _TsFile:
    """A parsed single file with helpers over tree-sitter nodes."""

    __slots__ = ("path", "source", "source_bytes", "tree", "root", "import_alias")

    def __init__(self, path: Path, source: str) -> None:
        self.path = path
        self.source = source
        self.source_bytes = source.encode("utf-8")
        parser = Parser(_TS_LANGUAGE)  # type: ignore[arg-type]
        self.tree = parser.parse(self.source_bytes)
        self.root = self.tree.root_node
        self.import_alias: dict[str, str] = {}
        self._collect_imports()

    # -- imports -----------------------------------------------------------

    def _collect_imports(self) -> None:
        """Map imported names -> full dotted names for callee resolution."""
        for node in _walk(self.root):
            if node.type != "import_statement":
                continue
            # `import a.b as c`  or  `import a.b`
            for child in node.children:
                if child.type in ("dotted_name", "alias"):
                    pass
            # Simpler: handle via dotted_name + alias children.
            names = [c for c in node.children if c.type == "dotted_name"]
            aliases = [c for c in node.children if c.type == "alias"]
            # tree-sitter python import_statement: dotted_name ( alias ',' )* dotted_name
            # We handle the common shapes below.
            for alias_node in aliases:
                alias_node_child = [c for c in alias_node.children if c.type != ","]
                if not alias_node_child:
                    continue
                name_node = alias_node_child[0]
                full = _node_text(name_node, self.source_bytes)
                as_node = [c for c in alias_node.children if c.type == "as"]
                if as_node:
                    target = _node_text([c for c in as_node[0].children if c.type == "identifier"][0], self.source_bytes)
                else:
                    target = full.split(".")[-1]
                self.import_alias[target] = full
            for name_node in names:
                full = _node_text(name_node, self.source_bytes)
                self.import_alias.setdefault(full.split(".")[-1], full)

        for node in _walk(self.root):
            if node.type != "import_from_statement":
                continue
            module_node = node.child_by_field_name("module_name")
            module = _node_text(module_node, self.source_bytes) if module_node is not None else ""
            for child in node.children:
                if child.type != "alias":
                    continue
                parts = [c for c in child.children if c.type not in (",", "as")]
                name = _node_text(parts[0], self.source_bytes) if parts else ""
                as_node = [c for c in child.children if c.type == "as"]
                if as_node:
                    target = _node_text([c for c in as_node[0].children if c.type == "identifier"][0], self.source_bytes)
                else:
                    target = name
                full = f"{module}.{name}" if module else name
                self.import_alias[target] = full

    # -- node helpers ------------------------------------------------------

    def callee_name(self, call_node) -> str | None:
        """Resolve the dotted callee name of a call node."""
        func = call_node.child_by_field_name("function")
        if func is None:
            return None
        if func.type == "identifier":
            return self._resolve(_node_text(func, self.source_bytes))
        if func.type == "attribute":
            return self._resolve(_attr_chain(func, self.source_bytes))
        return None

    def _resolve(self, name: str) -> str:
        return self.import_alias.get(name, name)

    def first_argument_node(self, call_node):
        """Return the first *positional* argument node of a call, or None."""
        args = call_node.child_by_field_name("arguments")
        if args is None:
            return None
        for child in args.children:
            if child.type in (",", "(", ")", "keyword_argument"):
                continue
            return child
        return None


def _walk(node):
    """Yield ``node`` and all named descendants, depth-first (tree-sitter)."""
    yield node
    for child in node.named_children:
        yield from _walk(child)


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8")


def _attr_chain(node, source_bytes: bytes) -> str:
    """Convert an attribute node to its dotted name (e.g. ``request.args.get``)."""
    parts: list[str] = []
    cur = node
    while cur.type == "attribute":
        attr = cur.child_by_field_name("attribute")
        obj = cur.child_by_field_name("object")
        if attr is None:
            break
        parts.append(_node_text(attr, source_bytes))
        cur = obj
    if cur.type == "identifier":
        parts.append(_node_text(cur, source_bytes))
    return ".".join(reversed(parts))


def _identifier_texts(node, source_bytes: bytes) -> list[str]:
    """All identifier texts appearing under ``node`` (depth-first, in order)."""
    names: list[str] = []
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == "identifier":
            names.append(_node_text(cur, source_bytes))
        # push children in reverse so left-to-right order is preserved
        stack.extend(reversed(cur.children))
    return names


def _assignment_of(stmt) -> object | None:
    """Return the inner ``assignment`` node of a statement, if any.

    tree-sitter wraps simple assignments in an ``expression_statement`` node.
    """
    if stmt is None:
        return None
    if stmt.type == "assignment":
        return stmt
    if stmt.type == "expression_statement":
        for child in stmt.children:
            if child.type == "assignment":
                return child
    return None


def _assignment_parts(assign_node):
    """Return ``(lhs_node, rhs_node)`` for an ``assignment`` node.

    This tree-sitter grammar exposes ``lhs``/``rhs`` positionally as
    ``[lhs, '=', rhs]`` rather than via named fields.
    """
    if assign_node is None or assign_node.type != "assignment":
        return None, None
    kids = [c for c in assign_node.children if c.type != "="]
    if not kids:
        return None, None
    if len(kids) == 1:
        return kids[0], None
    return kids[0], kids[1]


def _lhs_names(lhs_node, source_bytes: bytes) -> list[str]:
    """Variable names assigned by an assignment left-hand side."""
    if lhs_node is None:
        return []
    if lhs_node.type == "identifier":
        return [_node_text(lhs_node, source_bytes)]
    if lhs_node.type == "tuple":
        return [
            _node_text(c, source_bytes)
            for c in lhs_node.children
            if c.type == "identifier"
        ]
    return [_node_text(lhs_node, source_bytes)]


def _is_source(rhs_node, f: _TsFile) -> bool:
    """True if ``rhs`` reads user-controlled data into the assigned variable."""
    if rhs_node is None:
        return False
    if rhs_node.type == "call":
        callee = f.callee_name(rhs_node)
        if callee in _SOURCE_CALLS:
            return True
    if rhs_node.type == "attribute":
        if _attr_chain(rhs_node, f.source_bytes) in _SOURCE_CALLS:
            return True
    return False


def _has_route_decorators(decorators, source_bytes: bytes) -> bool:
    for dec in decorators:
        target = [c for c in dec.children if c.type not in ("@", ",")]
        if not target:
            continue
        d = target[0]
        name = ""
        if d.type == "call":
            func = d.child_by_field_name("function")
            if func is not None:
                name = (
                    _attr_chain(func, source_bytes)
                    if func.type == "attribute"
                    else _node_text(func, source_bytes)
                )
        elif d.type == "attribute":
            name = _attr_chain(d, source_bytes)
        elif d.type == "identifier":
            name = _node_text(d, source_bytes)
        if name in _ROUTE_DECORATORS:
            return True
    return False


def _collect_function_candidates(f: _TsFile):
    """Yield ``(func_node, decorator_nodes)`` pairs.

    tree-sitter 0.21 wraps route-decorated functions in a ``decorated_definition``
    node (decorator is a sibling of ``function_definition``); plain functions
    appear as bare ``function_definition`` nodes.
    """
    decorated_func_ids: set[int] = set()
    for node in _walk(f.root):
        if node.type == "decorated_definition":
            decorators = [c for c in node.children if c.type == "decorator"]
            funcs = [
                c
                for c in node.children
                if c.type in ("function_definition", "async_function_definition")
            ]
            if funcs:
                decorated_func_ids.add(id(funcs[0]))
                yield funcs[0], decorators
    for node in _walk(f.root):
        if (
            node.type in ("function_definition", "async_function_definition")
            and id(node) not in decorated_func_ids
        ):
            yield node, []


def _match_sink(callee: str | None) -> SinkType | None:
    if callee is None:
        return None
    if callee in _SINK_CALLEES:
        return _SINK_CALLEES[callee]
    if callee.endswith(".execute"):
        return SinkType.SQL_BUILD
    return None


def _slice_file_ts(f: _TsFile) -> list[CodeSlice]:
    slices: list[CodeSlice] = []
    source_lines = f.source.splitlines()

    for func_node, decorators in _collect_function_candidates(f):

        name_node = func_node.child_by_field_name("name")
        fn_name = (
            _node_text(name_node, f.source_bytes) if name_node is not None else "<lambda>"
        )
        start_point = func_node.start_point
        end_point = func_node.end_point
        start_line = start_point[0] + 1
        end_line = end_point[0] + 1
        function_body = "\n".join(source_lines[start_line - 1:end_line])

        # --- collect statements in order ---------------------------------
        body = func_node.child_by_field_name("body")
        statements = [c for c in (body.children if body is not None else [])]

        # --- taint analysis (fixed-point, intra-procedural) --------------
        tainted: set[str] = set()

        # Route-decorated handler parameters are entry points (e.g. FastAPI).
        if _has_route_decorators(decorators, f.source_bytes):
            params = func_node.child_by_field_name("parameters")
            if params is not None:
                for c in params.children:
                    if c.type == "identifier":
                        tainted.add(_node_text(c, f.source_bytes))

        # Fixed-point propagation over assignments.
        for _ in range(len(statements) + 3):
            changed = False
            for stmt in statements:
                assign = _assignment_of(stmt)
                if assign is None:
                    continue
                lhs, rhs = _assignment_parts(assign)
                lhs_names = _lhs_names(lhs, f.source_bytes)
                if not lhs_names:
                    continue
                if _is_source(rhs, f):
                    for n in lhs_names:
                        if n not in tainted:
                            tainted.add(n)
                            changed = True
                    continue
                if rhs is not None:
                    rhs_names = _identifier_texts(rhs, f.source_bytes)
                    for n in lhs_names:
                        if n not in tainted and any(r in tainted for r in rhs_names):
                            tainted.add(n)
                            changed = True
            if not changed:
                break

        # --- sinks ---------------------------------------------------------
        # Collect every call node in the function body, including calls nested
        # inside ``with`` statements, but do not descend into nested functions.
        call_nodes: list = []

        def _collect_calls(node):
            if node.type in ("function_definition", "async_function_definition"):
                return
            if node.type == "call":
                call_nodes.append(node)
                return
            for child in node.named_children:
                _collect_calls(child)

        for stmt in statements:
            _collect_calls(stmt)

        for call_node in call_nodes:
            callee = f.callee_name(call_node)
            sink_type = _match_sink(callee)
            if sink_type is None:
                continue

            first_arg = f.first_argument_node(call_node)
            if first_arg is None:
                continue
            arg_names = _identifier_texts(first_arg, f.source_bytes)
            if not any(n in tainted for n in arg_names):
                continue

            sink_line = call_node.start_point[0] + 1
            snippet_start = max(1, sink_line - 2)
            snippet_end = min(len(source_lines), sink_line + 2)
            context_snippet = "\n".join(source_lines[snippet_start - 1:snippet_end])

            entry_point = ""
            for dec in decorators:
                entry_point = _decorator_route(dec, f.source_bytes)
                if entry_point:
                    break

            slices.append(
                CodeSlice(
                    file_path=str(f.path),
                    start_line=start_line,
                    end_line=end_line,
                    function_name=fn_name,
                    function_body=function_body,
                    entry_point=entry_point,
                    sink_type=sink_type,
                    sink_line=sink_line,
                    imports=list(f.import_alias.keys()),
                    language="python",
                    context_snippet=context_snippet,
                )
            )

    return slices


def _decorator_route(decorator_node, source_bytes: bytes) -> str:
    """Extract the route path string from a route decorator, if any."""
    target = [c for c in decorator_node.children if c.type not in ("@", ",")]
    if not target:
        return ""
    dec = target[0]
    # `app.route("/ping")`  or  `app.get("/ping")`
    call_node = dec if dec.type == "call" else None
    if call_node is None:
        return ""
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return ""
    for c in args.children:
        if c.type == "string":
            raw = _node_text(c, source_bytes)
            return raw.strip('"').strip("'")
    return ""


# ---------------------------------------------------------------------------
# stdlib ast fallback
# ---------------------------------------------------------------------------

def _slice_file_ast(path: Path, source: str) -> list[CodeSlice]:
    """Fallback slicer using the stdlib ``ast`` module (offline, deterministic)."""
    slices: list[CodeSlice] = []
    source_lines = source.splitlines()
    tree = _ast.parse(source, filename=str(path))

    import_alias: dict[str, str] = {}
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            for a in node.names:
                full = a.name
                import_alias[a.asname or a.name.split(".")[-1]] = full
        elif isinstance(node, _ast.ImportFrom):
            module = node.module or ""
            for a in node.names:
                full = f"{module}.{a.name}" if module else a.name
                import_alias[a.asname or a.name] = full

    def resolve(name: str) -> str:
        return import_alias.get(name, name)

    for node in _ast.walk(tree):
        if not isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            continue

        fn_name = node.name
        start_line = node.lineno
        end_line = getattr(node, "end_lineno", start_line)
        function_body = "\n".join(source_lines[start_line - 1:end_line])

        tainted: set[str] = set()

        # Route-decorated handler parameters are entry points.
        is_route = any(
            (
                isinstance(d, _ast.Attribute) and resolve(d.attr) in _ROUTE_DECORATORS
            )
            or (
                isinstance(d, _ast.Call) and isinstance(d.func, _ast.Attribute)
                and resolve(d.func.attr) in _ROUTE_DECORATORS
            )
            for d in node.decorator_list
        )
        if is_route:
            for a in node.args.args:
                tainted.add(a.arg)

        # Propagate taint through assignments (single pass is enough for the
        # common source->sink patterns; a second pass covers short chains).
        assignments = [
            n for n in node.body if isinstance(n, (_ast.Assign, _ast.AnnAssign))
        ]
        for _ in range(3):
            changed = False
            for stmt in assignments:
                if isinstance(stmt, _ast.Assign):
                    targets = [
                        t.id for t in stmt.targets if isinstance(t, _ast.Name)
                    ]
                    value = stmt.value
                else:
                    targets = [stmt.target.id] if isinstance(stmt.target, _ast.Name) else []
                    value = stmt.value
                if not targets:
                    continue
                if _ast_source_call(value, import_alias):
                    for n in targets:
                        if n not in tainted:
                            tainted.add(n)
                            changed = True
                    continue
                refs = _ast_names(value)
                for n in targets:
                    if n not in tainted and any(r in tainted for r in refs):
                        tainted.add(n)
                        changed = True
            if not changed:
                break

        # Sinks: inspect calls nested in ``with`` and other compound statements,
        # while keeping the analysis intra-procedural.
        calls: list[_ast.Call] = []
        for descendant in _ast.walk(node):
            if descendant is node:
                continue
            if isinstance(descendant, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.Lambda)):
                continue
            if isinstance(descendant, _ast.Call):
                calls.append(descendant)

        for call in calls:
                callee = _ast_callee_name(call, import_alias)
                sink_type = _match_sink(callee)
                if sink_type is None:
                    continue
                args = call.args
                if not args:
                    continue
                arg_names = _ast_names(args[0])
                if not any(n in tainted for n in arg_names):
                    continue
                sink_line = getattr(call, "lineno", start_line)
                snippet_start = max(1, sink_line - 2)
                snippet_end = min(len(source_lines), sink_line + 2)
                context_snippet = "\n".join(source_lines[snippet_start - 1:snippet_end])
                slices.append(
                    CodeSlice(
                        file_path=str(path),
                        start_line=start_line,
                        end_line=end_line,
                        function_name=fn_name,
                        function_body=function_body,
                        entry_point=_ast_route_path(node, import_alias),
                        sink_type=sink_type,
                        sink_line=sink_line,
                        imports=list(import_alias.keys()),
                        language="python",
                        context_snippet=context_snippet,
                    )
                )
    return slices


def _ast_route_path(node: _ast.FunctionDef | _ast.AsyncFunctionDef, import_alias: dict[str, str]) -> str:
    """Return the first literal route path from a Flask/FastAPI decorator."""
    for decorator in node.decorator_list:
        if not isinstance(decorator, _ast.Call) or not isinstance(decorator.func, _ast.Attribute):
            continue
        if _ast_attr_chain(decorator.func) not in _ROUTE_DECORATORS:
            continue
        if decorator.args and isinstance(decorator.args[0], _ast.Constant):
            value = decorator.args[0].value
            if isinstance(value, str):
                return value
    return ""


def _ast_source_call(value, import_alias: dict[str, str]) -> bool:
    if isinstance(value, _ast.Call):
        callee = _ast_callee_name(value, import_alias)
        if callee in _SOURCE_CALLS:
            return True
    if isinstance(value, _ast.Attribute):
        return _ast_attr_chain(value) in _SOURCE_CALLS
    return False


def _ast_callee_name(call: _ast.Call, import_alias: dict[str, str]) -> str | None:
    func = call.func
    if isinstance(func, _ast.Name):
        return resolve_local(func.id, import_alias)
    if isinstance(func, _ast.Attribute):
        return _ast_attr_chain(func)
    return None


def resolve_local(name: str, import_alias: dict[str, str]) -> str:
    return import_alias.get(name, name)


def _ast_attr_chain(node: _ast.Attribute) -> str:
    parts: list[str] = []
    cur: _ast.AST | None = node
    while isinstance(cur, _ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, _ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _ast_names(node: _ast.AST) -> list[str]:
    names: list[str] = []
    for child in _ast.walk(node):
        if isinstance(child, _ast.Name):
            names.append(child.id)
    return names


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def slice_file(path: str | Path) -> list[CodeSlice]:
    """Slice a single Python file into taint-path :class:`CodeSlice` objects."""
    path = Path(path)
    source = path.read_text(encoding="utf-8")
    if _HAS_TREE_SITTER:
        f = _TsFile(path, source)
        tree_sitter_slices = _slice_file_ts(f)
        # The stdlib AST path handles compound statements more completely
        # across tree-sitter grammar versions while remaining deterministic.
        ast_slices = _slice_file_ast(path, source)
        if len(ast_slices) >= len(tree_sitter_slices):
            return ast_slices
        return tree_sitter_slices
    return _slice_file_ast(path, source)


def scan_repo(repo_path: str | Path) -> list[CodeSlice]:
    """Scan every ``.py`` file under ``repo_path`` and return all taint slices.

    Results are sorted by ``(file_path, start_line, sink_type)`` for
    determinism.
    """
    repo = Path(repo_path)
    slices: list[CodeSlice] = []
    if not repo.exists():
        return slices
    for path in sorted(repo.rglob("*.py")):
        try:
            slices.extend(slice_file(path))
        except Exception:
            # A single unparseable file must not abort the whole scan.
            continue
    slices.sort(key=lambda s: (s.file_path, s.start_line, str(s.sink_type)))
    return slices
