from django.contrib import admin
from bc_signature.models import WalletAccount, RSAAccount

admin.site.register(WalletAccount)
admin.site.register(RSAAccount)

