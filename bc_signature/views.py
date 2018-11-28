from django.shortcuts import render,redirect
from django.template import loader
from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.views import generic
from django.contrib import messages
from django.views import generic
from django.urls import reverse_lazy
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import views as base_auth_view
import requests
from bc_signature import models, my_rsa
import json
# ---- for RSA- 
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

from ast import literal_eval # convert string to tuple
#-----
from eth_account import Account
import base64
import json
import random

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
            return redirect('bc_signature:login')
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

            # list_node = get_all_nodes()
            # url = list_node[random.randrange(0,len(list_node)-1)]
            # print(" url register wallet ", url)
            # rep = requests.get(f'http://{url}/account/{id_user}')
            # data = rep.text
            # data = json.loads
            for i in range(2200, 2210):
                try:
                    rep = requests.post(f'http://172.30.0.1:{i}/account/{id_user}')
                    data = rep.text
                    print(type(data))
                    print(data)
                    data = json.loads(data)
                    if data:
                        break
                    else:
                        pass
                except:
                    pass
            # save json in models:
            wallet.user = u
            wallet.wallet_private_key = data['private_key']
            wallet.wallet_account  = data['address']
            wallet.save()
        else:
            data = 'user already have an wallet account '
            info = ""
            for item in list_user_id_in_wallets:
                if id_user == item:
                    i = models.WalletAccount.objects.get(user=u)
                    info = f"account : {i.wallet_account}"
                    print(i.wallet_account)
                    print(i.wallet_private_key)
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
            # prikey = RSA.generate(1024)
            # pubkey = prikey.publickey()
            # save json in models:
            pub_string, pri_string = my_rsa.pri_key()
            rsa_key.user = u
            rsa_key.rsa_private_key = pri_string #prikey.exportKey().decode() # save the key in DB by String
            rsa_key.rsa_public_key  = pub_string  #pubkey.exportKey().decode()
            rsa_key.save()
            print('sau khi luu vao DB 2 ',type(pri_string)) # <class 'bytes'>
            data = f'publickey = {pub_string} and private key = {pri_string}'
        else:
            data = 'user already have an rsa keypair  '
            info = ""
            for item in list_user_id_has_rsa_key:
                if id_user == item:
                    i = models.RSAAccount.objects.get(user=u)
                    pub = i.rsa_public_key
                    pri = i.rsa_private_key
                    print(type(pub))
                    print(pub)
                    print(pri)
                    print(len(pub)) # 271
                    print(len(pri))  #882
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


def check_RSA_account_exist_template(user_id):
    list_user_id_has_rsa_key = []
    u = models.User.objects.get(id=user_id)
    rsa_keys = models.RSAAccount.objects.all()
    for key in rsa_keys:
            list_user_id_has_rsa_key.append(key.user.id)
    if u.id not in list_user_id_has_rsa_key:
        return render(request,'base.html', {
            'check_RSA':False  # user chua co key
            })
    else:
        return render(request,'base.html', {
                'check_RSA': True #user cho roi
            })


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


def check_wallet_account_exist_template(user_id):
    list_user_id_has_wallet_key = []
    u = models.User.objects.get(id=user_id)
    wallet_keys = models.WalletAccount.objects.all()
    for key in wallet_keys:
            list_user_id_has_wallet_key.append(key.user.id)
    if u.id not in list_user_id_has_wallet_key:
        return render(request,'base.html', {
            'check_wallet':False  # user chua co key
            })
    else:
        return render(request,'base.html', {
                'check_wallet': True #user cho roi
            })
        

def get_all_nodes():
    list_node = []
    for i in range(2200, 2210):
        try:
            print(" i = ", i)
            # get list of nodes 
            rep = requests.get(f'http://172.30.0.1:{i}/nodes')
            list_node = json.loads(rep.text)
            print("cac node: ",list_node)
            if list_node:
                print(" okie")
                break
            else:
                pass
        except:
            pass
            
    return list_node['nodes']



def sign_contract(request):
    list_user_RSA = []
    list_user = models.User.objects.exclude(id = request.user.id)
    for i in list_user:
        do_have_RSA, _ = check_RSA_account_exist(i.id)
        do_have_wallet, _ = check_wallet_account_exist(i.id)
        if do_have_RSA and do_have_wallet:
            print("CO")
            list_user_RSA.append(i)
        else:
            print("CHUA CO")
    # try:
    if request.method == 'POST':
        content = request.POST['content']
        print("NOi DUNG",content)
        b_side = request.POST.get('B_side')
        print(" DA CHON: ",b_side)
        
        # if do_have_RSA and do_have_wallet:
        #     rsa_key = models.RSAAccount.objects.get(user = chosen_user)
        #     print("KEY: ",rsa_key.rsa_public_key)

        if request.user.is_authenticated:
            id_user = request.user.id
            print("user hien tai : ", request.user.username)
            result_rsa, list_user_id_has_rsa_key = check_RSA_account_exist(id_user)
            result_wallet , list_user_id_in_wallets = check_wallet_account_exist(id_user)

            chosen_user = models.User.objects.get(username = b_side)
            # do_have_RSA, _ = check_RSA_account_exist(chosen_user.id)
            # do_have_wallet, _ = check_wallet_account_exist(chosen_user.id)
            
            if result_rsa and result_wallet:
                # sign use private key
                i = models.RSAAccount.objects.get(user=request.user)
                j = models.RSAAccount.objects.get(user=chosen_user)

                k = models.WalletAccount.objects.get(user=chosen_user)
                wallet = models.WalletAccount.objects.get(user=request.user)
                    
                pub = i.rsa_public_key
                pri = i.rsa_private_key
                
                pub_b = j.rsa_public_key
                account_b = k.wallet_account
                #encrypt contract:
                encrypt_content = my_rsa.encrypt(content, pub_b)
                
                #sign:
                signature = my_rsa.sign(encrypt_content, pri) #int
                
                #verify:
                result = my_rsa.verify(encrypt_content, signature, pub)
                # pub_import = RSA.importKey(pub)
                # pri_import = RSA.importKey(pri)
                
                # h = SHA.new(content.encode())
                # print( " h = ", h)
                # signer = PKCS1_v1_5.new(pri_import)
                # signature = signer.sign(h)
                # # sig = prikey.sign(message.encode(),10)
                # print ( " signature: ")
                # print(signature)
                
                # luu = base64.b64encode(signature)
                # sign = luu.decode() # str >> save
                # print ("sign = ")
                # print(sign)
                # # verify:
                # verifier = PKCS1_v1_5.new(pub_import)
                # result = verifier.verify(h, signature)
                print("ket qua = ",result)
                
                
                # signature_json = json.dumps(signature).encode()
                # print("signature_json = ", signature_json)
                # print(signature_json)
                # print(type(signature_json))
                # verify:
                
                # chyen signature tu bytes thanh string
                # signature_json_ = signature_json.decode()

                # chuuyen signature tu string thanh list
                # sign = json.loads(signature_json)

                # chuyen signature tu list thanh tuple:
                # sign1 = tuple(sign)

                # result = pub_import.verify(content.encode(), sign1)
                
                # save on blokchhain: 
                if result:
                    list_node = get_all_nodes()
                    # random
                    url = list_node[random.randrange(0,len(list_node)-1)]
                    print("Node verify and save in transaction:", url)
                    print(" dung roi:")
                    
                    transaction = {
                        'from': wallet.wallet_account,
                        'to':account_b, #url,
                        'data':
                        {
                            'text': str(encrypt_content),
                            'signature': str(signature),
                            'public_key': pub,
                            'user_id': id_user,
                            'username': request.user.username
                        }
                    }
                    print("Transaction moi: ", transaction)
                    rep = requests.post(f'http://{url}/transactions', headers=headers, data= json.dumps(transaction))
                    if rep.text:
                        print("OKIE")
                    
                    messages.error(request, "Successful")
            
            elif not result_rsa:
                messages.error(request, "You should need a RSA account")
            elif not result_wallet:
                messages.error(request, "You should need a wallet account ")
        else:
            messages.error(request, 'You have to login!')
        return render(request, 'sign_rsa.html', {'list_user': list_user_RSA})
    # except:
    else:
        print("AHIHI")
        return render(request, 'sign_rsa.html', {'list_user': list_user_RSA})


def list_transaction_for_b_side(request):
    result , list_user_id_in_wallets = check_wallet_account_exist(request.user.id)
    print( result , ' dsdsds , ', list_user_id_in_wallets[0])
    if result:
        mess = ''
        wallet = models.WalletAccount.objects.get(user=request.user)
        account = wallet.wallet_account
        print(" ac = ", account)
        list_node = get_all_nodes()
        url = list_node[random.randrange(0,len(list_node)-1)]
        print(" url get transactions in b_side: ", url)
        rep = requests.get(f'http://{url}/transactions/{account}/b_side')

        data = rep.text
        
        data = json.loads(data)
        
        list_info_transaction = data['result']
        username = request.user.username
        if len(list_info_transaction) == 0:
            mess = f'User @{username} does not have any transaction yet'
        for i in list_info_transaction:
            print(" thong tin = ", i['transaction_hash'])

        return render(request, 'get_transactions.html', {
            'user_': request.user,
            'mess': mess,
            'list_info_transaction':list_info_transaction})
    else:
        return render(request,'get_transactions.html', {
            'user_': request.user,
            'mess': "User does not have a wallet account yet"

        })
# def b_side_check_contract(request):


def list_all_user(request):
    if request.user:
        users = models.User.objects.exclude(id = request.user.id).exclude(is_superuser=True)
    else:
        users = models.User.objects.exclude(is_superuser=True)
    return render(request,'all_user.html', {
        'users': users
        
    })


def list_transaction_by_account(request, username):
    user_ = models.User.objects.get(username = username)
    result , list_user_id_in_wallets = check_wallet_account_exist(user_.id)
    print( result , ' dsdsds , ', list_user_id_in_wallets[0])
    if result:
        mess = ''
        wallet = models.WalletAccount.objects.get(user=user_)
        account = wallet.wallet_account
        print(" ac = ", account)
        list_node = get_all_nodes()
        url = list_node[random.randrange(0,len(list_node)-1)]
        print(" url get transaction: ", url)
        rep = requests.get(f'http://{url}/transactions/{account}')
        data = rep.text
        data = json.loads(data)
        list_info_transaction = data['result']
        username = user_.username
        if len(list_info_transaction) == 0:
            mess = f'User @{username} does not have any transaction yet'
        for i in list_info_transaction:
            print(" thong tin = ", i['transaction_hash'])
        
        return render(request, 'get_transactions.html', {
            'user_': user_,
            'mess': mess,
            'list_info_transaction':list_info_transaction})
    else:
        return render(request,'get_transactions.html', {
            'user_': user_,
            'mess': "User does not have a wallet account yet"

        })


def list_transaction_of_current_user(request):
    result , list_user_id_in_wallets = check_wallet_account_exist(request.user.id)
    print( result , ' dsdsds , ', list_user_id_in_wallets[0])
    if result:
        mess = ''
        wallet = models.WalletAccount.objects.get(user=request.user)
        account = wallet.wallet_account
        print(" ac = ", account)
        list_node = get_all_nodes()
        url = list_node[random.randrange(0,len(list_node)-1)]
        print(" url get transactions: ", url)
        rep = requests.get(f'http://{url}/transactions/{account}')

        data = rep.text
        
        data = json.loads(data)
        
        list_info_transaction = data['result']
        username = request.user.username
        if len(list_info_transaction) == 0:
            mess = f'User @{username} does not have any transaction yet'
        for i in list_info_transaction:
            print(" thong tin = ", i['transaction_hash'])

        return render(request, 'get_transactions.html', {
            'user_': request.user,
            'mess': mess,
            'list_info_transaction':list_info_transaction})
    else:
        return render(request,'get_transactions.html', {
            'user_': request.user,
            'mess': "User does not have a wallet account yet"

        })


def detail_transaction(request, transaction_hash):
    info = ''
    list_node = get_all_nodes()
    url = list_node[random.randrange(0,len(list_node)-1)]
    print(" url get detail transaction: ", url)
    
    rep = requests.get(f'http://{url}/transaction/{transaction_hash}')
    data = rep.text
    
    # print(type(data))
    data = json.loads(data)
    info_1_transaction = data['result']
    pub = info_1_transaction['data']['public_key']
    encrypt_content = info_1_transaction['data']['text']
    signature = int(info_1_transaction['data']['signature'])
    print("list_info_transaction = ", info_1_transaction)

    # decrypt:
    wallet = models.WalletAccount.objects.get(user = request.user)
    rsa = models.RSAAccount.objects.get(user=request.user)
    show_contract = None
    to = info_1_transaction['to']
    if to == wallet.wallet_account:
        show_contract = my_rsa.decrypt(int(encrypt_content), rsa.rsa_private_key)
            
    # return(request, 'detail_transaction.html') để lại nhắc nhở, code ngu, tốn mấy tiếng =.=
    return render(request, 'detail_transaction.html', {
        'info':info_1_transaction,
        'show_contract': show_contract
    })


def check_signature(request, transaction_hash):
    mess = ''
    list_node = get_all_nodes()
    url = list_node[random.randrange(0,len(list_node)-1)]
    print(" url get detail transaction: ", url)
    
    rep = requests.get(f'http://{url}/transaction/{transaction_hash}')
    data = rep.text
    
    data = json.loads(data)
    info_1_transaction = data['result']
    print("list_info_transaction = ", info_1_transaction)

    pub = info_1_transaction['data']['public_key']
    encrypt_content = info_1_transaction['data']['text']
    signature = int(info_1_transaction['data']['signature'])
  
    #verify:
    result = my_rsa.verify(int(encrypt_content), signature, pub)
    
    print("ket qua: ", result)

     # decrypt:
    wallet = models.WalletAccount.objects.get(user = request.user)
    rsa = models.RSAAccount.objects.get(user=request.user)
    show_contract = None
    to = info_1_transaction['to']
    if to == wallet.wallet_account:
        show_contract = my_rsa.decrypt(int(encrypt_content), rsa.rsa_private_key)

    return render(request, 'detail_transaction.html', {
        'verify':result,
        'info':info_1_transaction,
        'show_contract': show_contract
        })


def sign_transaction(request):
    # data = ''
    # list_user_id_in_wallets = []
    # if request.user.is_authenticated:
    #     id_user = request.user.id
    #     u = models.User.objects.get(id=id_user)
    #     result , list_user_id_in_wallets = check_wallet_account_exist(id_user)
    #     if not result:
    #         wallet = models.WalletAccount() 
            
    #         list_node = get_all_nodes()
    #         url = list_node[random.randrange(0,len(list_node)-1)]
    #         print(" url register wallet ", url)
    #         rep = requests.get(f'http://{url}/account/{id_user}')
    #         data = rep.text

    #         # save json in models:
    #         wallet.user = u
    #         wallet.wallet_private_key = data['private_key']
    #         wallet.wallet_account  = data['address']
    #         wallet.save()
    #     else:
    #         data = 'user already have an wallet account '
    #         info = ""
    #         for item in list_user_id_in_wallets:
    #             if id_user == item:
    #                 i = models.WalletAccount.objects.get(user=u)
    #                 info = f"account : {i.wallet_account}"
    #                 print(i.wallet_account)
    #                 print(i.wallet_private_key)
    #         data += info
    # else:
    #     data = "User need to log in!"  

    wallet = models.WalletAccount.objects.get(user = request.user)
    transaction = {
        'from': wallet.wallet_account,
        'value':123,
        'gas':1000000,
        'gasPrice':200,
        'nonce':0,
        'chainId':1996
    }
    signed = Account.signTransaction(transaction, wallet.wallet_private_key)
    print("ket qua: ", signed)
    print(signed['rawTransaction'].hex())
    print(type(signed['rawTransaction'].hex()))

    return render(request, 'base.html', {'signed': signed['rawTransaction'].hex()
        })