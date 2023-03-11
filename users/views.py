from users.serializers import SignUpSerializer, ChangeUserInformationSerializer, MyTokenObtainPairSerializer, \
    CustomTokenRefreshSerializer, LogoutSerializer
from rest_framework.generics import CreateAPIView, UpdateAPIView, GenericAPIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework.status import HTTP_205_RESET_CONTENT, HTTP_400_BAD_REQUEST
from users.models import User, CODE_VERIFIED, DONE, VIA_EMAIL, VIA_PHONE
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.tokens import TokenError
from rest_framework.exceptions import ValidationError
from shared.utils import send_email, send_phone
from rest_framework.response import Response
from rest_framework.views import APIView
from datetime import datetime


class CreateUserView(CreateAPIView):
    model = User
    serializer_class = SignUpSerializer
    permission_classes = (AllowAny,)


class LoginView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


class LogoutView(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = self.request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = {
                'success': True,
                'message': 'You are logged out'
            }
            return Response(data=data, status=HTTP_205_RESET_CONTENT)
        except TokenError:
            return Response(status=HTTP_400_BAD_REQUEST)


class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer


class VerifyApiView(APIView):
    def post(self, request, *args, **kwargs):
        user, code = request.user, request.data.get('code')
        self.check_verify(user, code)
        return Response(
            data={
                'success': True,
                'auth_status': user.auth_status,
                'access': user.tokens()['access'],
                'refresh': user.tokens()['refresh']
            }, status=200
        )

    @staticmethod
    def check_verify(user, code):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), code=code, is_confirmed=False)
        if not verifies.exists():
            data = {
                'message': 'Code is incorrect or expired!'
            }
            raise ValidationError(data)
        verifies.update(is_confirmed=True)
        if user.auth_type not in DONE:
            user.auth_status = CODE_VERIFIED
            user.save()
        return True


class GetNewVerification(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user
        self.check_verification(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_phone(user.phone_number, code)
        else:
            data = {
                'message': 'You need to enter email or phone number!'
            }
            raise ValidationError(data)
        return Response({
            'success': True
        })

    @staticmethod
    def check_verification(user):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), is_confirmed=False)
        if verifies.exists():
            data = {
                'message': 'You need to wait over expiration time!'
            }
            raise ValidationError(data)


class ChangeUserInformationView(UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangeUserInformationSerializer
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).partial_update(request, *args, **kwargs)

        return Response(
            data={
                'detail': 'Updated Successfully!',
                'auth_status': self.request.user.auth_status
            }, status=200
        )
