from django.urls import path
import bc_signature.views as bc_signature_views
from django.views.generic.base import TemplateView
from django.contrib.auth.views import logout
from django.conf import settings

app_name = 'bc_signature'
urlpatterns = [
    # path('', TemplateView.as_view(template_name='base.html'), name='home'),
    path('login/', bc_signature_views.Login.as_view(), name='login'),
    path('signup/', bc_signature_views.Signup, name='signup'),
    path('logout/', logout, {'next_page': settings.LOGOUT_REDIRECT_URL}, name='logout'),
    # main url
    path('register_wallet/', bc_signature_views.RegisterWallet, name='get_wallet'),
    path('register_rsa/', bc_signature_views.ResgisterRSA, name='get_rsa_account'),
    path('sign/', bc_signature_views.sign_contract, name='sign'),
    path('my_transactions/', bc_signature_views.list_transaction_of_current_user, name = 'my_transactions'),
    path('my_transactions/b_side', bc_signature_views.list_transaction_for_b_side, name = 'my_transactions_b_side'),
    path('detail_transaction/<str:transaction_hash>', bc_signature_views.detail_transaction, name = 'detail_transaction'),
    path('check_signature/<str:transaction_hash>', bc_signature_views.check_signature, name = 'check_signature'),
    path('sign_transaction/', bc_signature_views.sign_transaction, name = 'sign_transaction'),
    path('', bc_signature_views.list_all_user, name = 'home'),
    path('transactions_of_user/<str:username>', bc_signature_views.list_transaction_by_account, name = 'transactions_of_user')
    
    
]
