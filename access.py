from functools import wraps

from astrbot.api.event import filter


def admin_command(name):
    """Require AstrBot admin even if a host command override relaxes the filter."""
    def register(handler):
        @filter.permission_type(filter.PermissionType.ADMIN)
        @filter.command(name)
        @wraps(handler)
        async def checked(self, event, *args, **kwargs):
            if not event.is_admin():
                yield event.plain_result("仅 AstrBot 管理员可使用此命令。")
                return
            async for result in handler(self, event, *args, **kwargs):
                yield result

        return checked

    return register
