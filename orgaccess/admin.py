from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from . import models

admin.site.register(models.User, UserAdmin)
for m in (models.Department, models.Role, models.AccessGroup, models.TemporaryGrant,
          models.Document, models.DocumentChunk, models.PrivateItem,
          models.Tool, models.ToolGrant, models.AuditLog):
    admin.site.register(m)
