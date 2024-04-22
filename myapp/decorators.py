import requests
from jose import jwt, JWTError
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings

def cognito_auth_required(function):
    def wrap(view, request, *args, **kwargs):
        # Extrair o token do cabeçalho Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return Response({'error': 'Authorization token is missing or invalid'}, status=status.HTTP_401_UNAUTHORIZED)

        # Remover o prefixo 'Bearer ' para obter o token real
        token = auth_header[7:]

        try:
            # Obter o JSON Web Key Set (JWKS)
            key_url = f"https://cognito-idp.{settings.AWS_REGION}.amazonaws.com/{settings.COGNITO_USER_POOL_ID}/.well-known/jwks.json"
            response = requests.get(key_url)
            jwks = response.json()

            # Decodificar o token
            claims = jwt.decode(
                token,
                jwks,
                algorithms=['RS256'],
                audience=settings.COGNITO_CLIENT_ID,
                issuer=f"https://cognito-idp.{settings.AWS_REGION}.amazonaws.com/{settings.COGNITO_USER_POOL_ID}"
            )

            # Adicionar claims ao objeto request para uso posterior
            request.user_claims = claims

        except JWTError as e:
            return Response({'error': str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': 'Failed to decode token: ' + str(e)}, status=status.HTTP_401_UNAUTHORIZED)

        # Continuar para a função envolvida com o token validado
        return function(view, request, *args, **kwargs)

    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap
