from django.contrib import admin
from account.models import PortalUser


admin.site.register(PortalUser)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email')
    search_fields = ('username',)
    fieldsets = (
        (None, {
            'classes': ['wide'],
            'fields': ('username', 'password')
        }),
        ('Informations personnelles', {
            'classes': ['wide'],
            'fields': ('first_name', 'last_name', 'email', 'avatar')
        }),
        ('Permissions', {
            'classes': ['wide'],
            'fields': ('is_superuser', 'is_staff', 'is_active', 'groups', 'permissions')
        }),
        ('Dates importantes', {
            'classes': ['wide'],
            'fields': ('last_login', 'date_joined')
        }),
    )




