from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import login, logout,authenticate
from .forms import TodoForm
from .models import Todo

def home(req):
    if req.user.is_authenticated:
        if req.method == 'GET':
            todos=Todo.objects.all()
            return render(req,'todo/home.html',{'form':TodoForm(),'todos':todos})
        else:
            form = TodoForm(req.POST)
            newtodo = form.save(commit=False)
            newtodo.user = req.user
            newtodo.save()
            return redirect('home')
    if req.method == 'GET':
        return render(req, 'todo/home.html',{'form': AuthenticationForm()})
    else:
        user = authenticate(req,username =req.POST['username'],password = req.POST['password'])
        if user is None:
            return render(req, 'todo/home.html',{'form': AuthenticationForm(),'error':'Incorrect login or password'})
        else:
            login(req, user)
            return redirect('home')

def signupuser(req):
    if req.method == 'GET':

        return render(req, 'todo/signupuser.html', {'form': UserCreationForm()})
    else:
        if req.POST['password1'] == req.POST['password2']:
            try:
                user = User.objects.create_user(
                    req.POST['username'], password=req.POST['password1'])
                user.save()
                login(req, user)
                return redirect('currenttodos')
            except IntegrityError:
                return render(req, 'todo/signupuser.html', {'form': UserCreationForm(), 'error': 'Nickname busy'})

        else:
            return render(req, 'todo/signupuser.html', {'form': UserCreationForm(), 'error': 'Password mismatch'})


def logoutuser(req):
    if req.method == 'POST':
        logout(req)
        return redirect('home')


def loginu(req):

    return render(req, 'todo/login.html', {'form': AuthenticationForm()})
