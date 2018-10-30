from django.shortcuts import render
from django.views import generic
from django.urls import reverse_lazy
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import views as base_auth_view
import requests
from bc_signature import models
import json
# class Signup(generic.CreateView):
#     form_class = UserCreationForm
#     success_url = reverse_lazy('bc_signature:login')
#     template_name = 'signup.html'
    
headers = {'content-type': 'application/json'}

def Signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'sign up successful')
            return redirect('login')
    else:
            form = UserCreationForm()
    return render(request, 'signup.html',{'form':form})


class Login(base_auth_view.LoginView):
    template_name = 'login.html'


def RegisterWallet(request):
    data = ''
    list_user_id_in_wallets = []
    if request.user.is_authenticated:
        id_user = request.user.id
        wallets = models.WalletAccount.objects.all() # list all wallet
        u = models.User.objects.get(id=id_user) # user hien tai.
       
        for w in wallets:
            list_user_id_in_wallets.append(w.user.id)
        
        if u.id not in list_user_id_in_wallets: # check if user had not created wallet account yet
            wallet = models.WalletAccount() 
            rep = requests.post(f'http://172.30.0.1:2202/account/{id_user}')
            data = rep.json()
            # save json in models:
            wallet.user = u
            wallet.wallet_private_key = data['private_key']
            wallet.wallet_account  = data['address']
            wallet.save()
        else:
            data = 'user already had an wallet account'
    else:
        data = "User need to log in!"           
    return render(request, 'get_account.html', {'data':data})


