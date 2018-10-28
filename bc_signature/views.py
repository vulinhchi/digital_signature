from django.shortcuts import render
from django.views import generic
from django.urls import reverse_lazy
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import views as base_auth_view

class Signup(generic.CreateView):
    form_class = UserCreationForm
    success_url = reverse_lazy('bc_signature:login')
    template_name = 'signup.html'


class Login(base_auth_view.LoginView):
    template_name = 'login.html'