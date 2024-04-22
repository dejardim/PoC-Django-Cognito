import boto3
import hmac
import hashlib
import base64
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer
from .decorators import cognito_auth_required


def get_secret_hash(username, client_id, client_secret):
    message = username + client_id
    key = bytes(client_secret, 'utf-8')
    message = bytes(message, 'utf-8')
    digester = hmac.new(key, message, hashlib.sha256)
    signature = digester.digest()
    secret_hash = base64.b64encode(signature).decode()
    return secret_hash

def create_cognito_user(email, password):
    client = boto3.client('cognito-idp', region_name=settings.AWS_REGION)
    secret_hash = get_secret_hash(email, settings.COGNITO_CLIENT_ID, settings.COGNITO_CLIENT_SECRET)
    try:
        sign_up_response = client.sign_up(
            ClientId=settings.COGNITO_CLIENT_ID,
            SecretHash=secret_hash,
            Username=email,
            Password=password,
        )

        client.admin_confirm_sign_up(
            UserPoolId=settings.COGNITO_USER_POOL_ID,
            Username=email
        )

        return sign_up_response
    except client.exceptions.UsernameExistsException:
        return {"error": "This username already exists"}

def authenticate_user(email, password):
    client = boto3.client('cognito-idp', region_name=settings.AWS_REGION)
    secret_hash = get_secret_hash(email, settings.COGNITO_CLIENT_ID, settings.COGNITO_CLIENT_SECRET)
    try:
        response = client.initiate_auth(
            ClientId=settings.COGNITO_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )
        return response['AuthenticationResult']['IdToken']
    except client.exceptions.NotAuthorizedException:
        return {"error": "The username or password is incorrect"}
    except client.exceptions.UserNotConfirmedException:
        return {"error": "User is not confirmed."}


class SignupView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            result = create_cognito_user(email, password)
            return Response(result)
        return Response(serializer.errors, status=400)

class LoginView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            result = authenticate_user(email, password)
            return Response(result)
        return Response(serializer.errors, status=400)

class ProtectedView(APIView):
    @cognito_auth_required
    def get(self, request):
        print(request.user_claims)
        return Response({'message': 'You are authenticated!', 'claims': request.user_claims})
