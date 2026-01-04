import json

from django.http import JsonResponse
from django.shortcuts import render
from rest_framework.views import APIView

from password_manager.services.view_services import ViewServices


class SignUp(APIView):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='signup.html')


class CreateMasterPasswordView(APIView):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='create_master_password')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)


class Login(APIView):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='login.html')

    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='login')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

class Home(APIView):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='home.html')

class ManagePasswords(APIView):
    def get(self, request, *args, **kwargs):
        pass

    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='create_password')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    def put(self, request, *args, **kwargs):
        pass
