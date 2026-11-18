import ast
import asyncio
import importlib.util
from pathlib import Path
from types import SimpleNamespace

from astrbot.core.star.filter.permission import PermissionType, PermissionTypeFilter
from astrbot.core.star.star_handler import star_handlers_registry


ROOT = Path(__file__).resolve().parents[1]


def test_sensitive_commands_require_admin_gate():
    tree = ast.parse((ROOT / "main.py").read_text(encoding="utf-8-sig"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        if not node.name.startswith("cmd_") or node.name in {"cmd_help", "cmd_check_admin"}:
            continue
        assert any(isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
                   and d.func.id == "admin_command" for d in node.decorator_list), node.name


def test_admin_gate_and_registration():
    spec = importlib.util.spec_from_file_location("test_guard_access", ROOT / "access.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    changes = []

    @module.admin_command("test_guard_access")
    async def sample(self, event, minutes: int = 5):
        changes.append(minutes)
        yield "ok"

    md = star_handlers_registry.get_handler_by_full_name(f"{__name__}_sample")
    try:
        gate = next(f for f in md.event_filters if isinstance(f, PermissionTypeFilter))
        assert gate.permission_type == PermissionType.ADMIN
        for is_admin, exempt in ((False, False), (False, True), (True, False)):
            event = SimpleNamespace(is_admin=lambda: is_admin, exempt=exempt, plain_result=str)
            assert gate.filter(event, {}) is is_admin

            async def run():
                return [item async for item in sample(None, event, 7)]

            assert (asyncio.run(run()) == ["ok"]) is is_admin
        assert changes == [7]
    finally:
        star_handlers_registry.remove(md)
