from django.db import models
from django.contrib.auth.models import User

class WalletAccount(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE,related_name='users_wallet')
    wallet_private_key = models.CharField( max_length=100,blank=True, null=True)
    wallet_account = models.CharField( max_length=100, blank=True, null=True)
    
    def __str__(self):
        return self.wallet_account


class RSAAccount(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE,related_name='users_rsa')
    rsa_private_key = models.CharField( max_length=1000, blank=True, null=True)
    rsa_public_key = models.CharField( max_length=1000, blank=True, null=True)

    def __str__(self):
        return self.user.username