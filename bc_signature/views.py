from django.shortcuts import render
from django.template import loader
from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.contrib import messages
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
        u = models.User.objects.get(id=id_user)
        result , list_user_id_in_wallets = check_wallet_account_exist(id_user)
        if not result:
            wallet = models.WalletAccount() 
            rep = requests.post(f'http://172.30.0.1:2202/account/{id_user}')
            data = rep.json()
            # save json in models:
            wallet.user = u
            wallet.wallet_private_key = data['private_key']
            wallet.wallet_account  = data['address']
            wallet.save()
        else:
            data = 'user already have an wallet account'
            info = ""
            for item in list_user_id_in_wallets:
                if id_user == item:
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
        u = models.User.objects.get(id=id_user)
        result, list_user_id_has_rsa_key = check_RSA_account_exist(id_user)
        if  not result:
            rsa_key = models.RSAAccount()
            prikey = RSA.generate(1024)
            pubkey = prikey.publickey()
            # save json in models:
            rsa_key.user = u
            rsa_key.rsa_private_key = prikey.exportKey().decode() # save the key in DB by String
            rsa_key.rsa_public_key  = pubkey.exportKey().decode()
            print('sau khi luu vao DB',type(rsa_key.rsa_private_key)) # <class 'bytes'>
            rsa_key.save()
            print('sau khi luu vao DB 2 ',type(rsa_key.rsa_private_key)) # <class 'bytes'>
            data = f'publickey = {pubkey} and private key = {prikey}'
        else:
            data = 'user already have an rsa keypair  '
            info = ""
            for item in list_user_id_has_rsa_key:
                if id_user == item:
                    i = models.RSAAccount.objects.get(user=u)
                    pub = i.rsa_public_key
                    pri = i.rsa_private_key
                    
                    info = f"publickey : {pub} and private_key: {pri}"
            data += info
    else:
        data = "User need to log in!"           
    return render(request, 'get_account.html', {'data':data})


def check_RSA_account_exist(user_id):
    list_user_id_has_rsa_key = []
    u = models.User.objects.get(id=user_id)
    rsa_keys = models.RSAAccount.objects.all()
    for key in rsa_keys:
            list_user_id_has_rsa_key.append(key.user.id)
    if u.id not in list_user_id_has_rsa_key:
        return False, list_user_id_has_rsa_key
    else:
        return True, list_user_id_has_rsa_key


def check_wallet_account_exist(user_id):
    list_user_id_has_wallet_key = []
    u = models.User.objects.get(id=user_id)
    wallet_keys = models.WalletAccount.objects.all()
    for key in wallet_keys:
            list_user_id_has_wallet_key.append(key.user.id)
    if u.id not in list_user_id_has_wallet_key:
        return False, list_user_id_has_wallet_key
    else:
        return True, list_user_id_has_wallet_key


def sign_contract(request):
    template_sign = loader.get_template('base.html')
    try:
        content = request.POST['content']
        print(content)
        if len(content) == 0:
            messages.error(request, 'You need to type something!')
        # check have user has RSA account and wallet account?
        if request.user.is_authenticated:
            id_user = request.user.id
            u = models.User.objects.get(id=id_user)
            result_rsa, list_user_id_has_rsa_key = check_RSA_account_exist(id_user)
            result_wallet , list_user_id_in_wallets = check_wallet_account_exist(id_user)
            if result_rsa and result_wallet:
                # sign
                for item in list_user_id_has_rsa_key:
                    if id_user == item:
                        i = models.RSAAccount.objects.get(user=u)
                        
                        pub = i.rsa_public_key
                        pri = i.rsa_private_key
                        
                        pub_import = RSA.importKey(pub)
                        pri_import = RSA.importKey(pri)
                        
                        signature = pri_import.sign(content.encode(),10)
                        
                        # verify:
                        result = pub_import.verify(content.encode(),signature)
                        print("ket qua: ", result)
                        # save on blokchhain: 
                        if result:
                            transaction = {
                                'from': "43430909990",
                                'to':'34jer84838',
                                'data':
                                {
                                    'text': content,
                                    'signature': signature,
                                    'public_key': pub,
                                    'user_id': id_user,
                                    'username': u.username
                                }
                            }
                            rep = requests.post('http://172.30.0.1:2201/transactions', headers=headers, data= json.dumps(transaction))
                            data = rep.json()
            
            elif not result_rsa:
                messages.error(request, "You should need a RSA account")
            elif not result_wallet:
                messages.error(request, "You should need a wallet account ")
        else:
            messages.error(request, 'You have to login!')
        return render(request, 'base.html')
    except:
        return render(request, 'base.html')