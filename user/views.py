from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
from .models import *
import jwt
from rest_framework import status
from django.shortcuts import get_object_or_404
from rest_framework import authentication
import django

# Create your views here.


class UserView(APIView):
    keyword = ['token', 'bearer']

    def authenticate(self, request):
        auth = authentication.get_authorization_header(request).split()

        if not auth:
            return None

        if auth[0].lower().decode() not in self.keyword:
            return None

        token = auth[1].decode()
        return token

    def get(self, request, userName):
        try:
            if not userName or userName == "":
                return self.ResponseData("error", "user name is required", status.HTTP_400_BAD_REQUEST)
            users = User.objects.all()
            Authorization = self.authenticate(request)
            isUserExists = get_object_or_404(users, userName=userName)
            if isUserExists:
                authTokenForUser = jwt.encode(
                    {'userName': userName}, 'secret', algorithm='HS256')
                print(authTokenForUser)
                if Authorization == authTokenForUser:
                    userSerializer = UserSerializer(users, many=True)
                    return (self.ResponseData('success', userSerializer.data, status.HTTP_201_CREATED))
                else:
                    return (self.ResponseData('error', userSerializer.errors, status.HTTP_400_BAD_REQUEST))

            return (self.ResponseData('error', "Unauthorised", status.HTTP_401_UNAUTHORISED))
        except Exception as e:
            print(e)
            return (self.ResponseData('error', 'something went wrong', status.HTTP_400_BAD_REQUEST))

    def post(self, request, userName):
        try:
            if not userName or userName == "":
                return self.ResponseData("error", "user name is required", status.HTTP_400_BAD_REQUEST)
            users = User.objects.all()
            Authorization = self.authenticate(request)
            isUserExists = get_object_or_404(users, userName=userName)
            if isUserExists:
                authTokenForUser = jwt.encode(
                    {'userName': userName}, 'secret', algorithm='HS256')
            print(authTokenForUser, "authTokenForUser")
            # print(Authorization == authTokenForUser)
            if Authorization == authTokenForUser:
                print(request.data)

                userSerializer = UserSerializer(data=request.data, many=False)
                if userSerializer.is_valid():
                    userSerializer.save()
                    return (self.ResponseData('success', userSerializer.data, status.HTTP_201_CREATED))
                else:
                    return (self.ResponseData('error', userSerializer.errors, status.HTTP_400_BAD_REQUEST))

            return (self.ResponseData('error', "Unauthorised", status.HTTP_401_UNAUTHORIZED))

        except django.http.response.Http404 as e:
            return self.ResponseData('error', e.args[0], status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(type(e))
            print(e, "exceprion")
            return (self.ResponseData('error', 'something went wrong', status.HTTP_400_BAD_REQUEST))

    def delete(self, request, userName):
        try:
            if not userName:
                self.ResponseData('error', 'username is required',
                                  status.HTTP_400_BAD_REQUEST)
            user = User.objects.get(userName=userName)
            Authorization = self.authenticate(request)
            print(user, Authorization)
            if user:
                authTokenForUser = jwt.encode(
                    {'userName': userName}, 'secret', algorithm='HS256')
                if (Authorization == authTokenForUser):
                    user.delete()
                    return self.ResponseData('success', 'user deleted successfully', status.HTTP_204_NO_CONTENT)
            return self.ResponseData('error', 'userName not found', status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist as e:
            return self.ResponseData('error', e.args[0], status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return self.ResponseData('error', e.args[0], status.HTTP_400_BAD_REQUEST)

    def patch(self, request, userName):
        try:
            if not userName or userName == "":
                return self.ResponseData("error", "user name is required", status.HTTP_400_BAD_REQUEST)
            users = User.objects.all()
            Authorization = self.authenticate(request)
            isUserExists = get_object_or_404(users, userName=userName)
            if isUserExists:
                authTokenForUser = jwt.encode(
                    {'userName': userName}, 'secret', algorithm='HS256')
            print(authTokenForUser, "authTokenForUser")
            # print(Authorization == authTokenForUser)
            if Authorization == authTokenForUser:
                userSerializer = UserSerializer(isUserExists,
                    data=request.data, many=False, partial=True)
                if userSerializer.is_valid():
                    userSerializer.save()
                    return (self.ResponseData('success', userSerializer.data, status.HTTP_201_CREATED))
                else:
                    return (self.ResponseData('error', userSerializer.errors, status.HTTP_400_BAD_REQUEST))

            return (self.ResponseData('error', "Unauthorised", status.HTTP_401_UNAUTHORIZED))

        except django.http.response.Http404 as e:
            return self.ResponseData('error', e.args[0], status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(type(e))
            print(e, "exceprion")
            return (self.ResponseData('error', 'something went wrong', status.HTTP_400_BAD_REQUEST))

    def ResponseData(self, status, data, statuscode):
        return Response(
            {
                'status': status,
                'data': data
            },
            status=statuscode
        )
