from django.shortcuts import render
from django.template import loader
from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.views import generic
from django.urls import reverse_lazy
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import views as base_auth_view
import requests
from bc_signature import models
import json
from Crypto.PublicKey import RSA

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
            info = ""
            for item in list_user_id_in_wallets:
                if u.id == item:
                    i = models.WalletAccount.objects.get(user=u)
                    info = f"account : {i.wallet_account} and private_key: {i.wallet_private_key}"
            data += info
    else:
        data = "User need to log in!"           
    return render(request, 'get_account.html', {'data':data})


def ResgisterRSA(request):
    data = ''
    list_user_id_has_rsa_key = []
    if request.user.is_authenticated:
        id_user = request.user.id
        rsa_keys = models.RSAAccount.objects.all()
        u = models.User.objects.get(id=id_user)
        mess = "ahihi"
        
        print(" kieu: ", RSA.generate(1024).exportKey())
        a = RSA.generate(1024)
        print(" a = ",type(a)) # <class 'Crypto.PublicKey.RSA._RSAobj'>
        for key in rsa_keys:
            list_user_id_has_rsa_key.append(key.user.id)
        if u.id not in list_user_id_has_rsa_key: # check if user had not created wallet account yet
            rsa_key = models.RSAAccount()
            prikey = RSA.generate(1024)
            print('type pri', prikey) # <_RSAobj @0x7fdee9260d68 n(1024),e,d,p,q,u,private>
            pubkey = prikey.publickey()
            print(type(prikey)) #<class 'Crypto.PublicKey.RSA._RSAobj'>
            # save json in models:
            rsa_key.user = u
            rsa_key.rsa_private_key = prikey.exportKey()
            rsa_key.rsa_public_key  = pubkey.exportKey()
            print('sau khi luu vao DB',type(rsa_key.rsa_private_key)) # <class 'bytes'>
            rsa_key.save()
            print('sau khi luu vao DB 2 ',type(rsa_key.rsa_private_key)) # <class 'bytes'>
            data = f'publickey = {pubkey} and private key = {prikey}'
        else:
            data = 'user already had an rsa keypair  '
            info = ""
            for item in list_user_id_has_rsa_key:
                if u.id == item:
                    i = models.RSAAccount.objects.get(user=u)
                    print(type(i.rsa_private_key)) #<class 'str'>
                    pub = i.rsa_public_key
                    pri = i.rsa_private_key
                    info = f"publickey : {pub} and private_key: {pri}"
            data += info
    else:
        data = "User need to log in!"           
    return render(request, 'get_account.html', {'data':data})

    
def sign_contract(request):
    template_sign = loader.get_template('base.html')
    try:
        content = request.POST['content']
        print(content)
        return HttpResponse(template_sign.render({
			'message': content
		}, request))
    except:
        return HttpResponse(template_sign.render({}, request))