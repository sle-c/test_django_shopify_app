import re
from django.conf import settings
from django.http import HttpResponseRedirect
from django.core.cache import cache
import jwt
from authlib.integrations.requests_client import OAuth2Session


class AuthResponse:
    shop = None
    access_token = None
    id_token = None
    redirect_url = None


class AuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response


    def process_view(self, request, view_func, view_args, view_kwargs):
        """
        This method allows us to use this middleware as a decorator
        """
        return self.__call__(request, view_args, view_kwargs)


    def __call__(self, request, view_args, view_kwargs):
        if settings.EMBEDDED:
            auth_response = self.__embedded(request)
        else:
            auth_response = self.__non_embedded(request)

        if auth_response.redirect_url is not None:
            return HttpResponseRedirect(auth_response.redirect_url)

        request.shop = auth_response.shop
        request.access_token = auth_response.access_token
        request.id_token = auth_response.id_token

        response = self.get_response(request, *view_args, **view_kwargs)
        self.__set_csp_headers(request, response)
        return response


    def __non_embedded(self, request):
        if 'shop' not in request.session:
            shop = self.__sanitize_shop(request.GET.get('shop'))
            if shop is not None:
                response = AuthResponse()
                response.redirect_url = f'/auth?shop={shop}'

                return response
            else:
                raise Exception('Could not find a shop session, request is not authenticated')

        response = AuthResponse()
        response.shop = request.session['shop']
        response.access_token = request.session['access_token']

        return response


    def __embedded(self, request):
        id_token = None
        if 'id_token' in request.GET:
            id_token = request.GET['id_token']
        elif 'Authorization' in request.headers:
            id_token = request.headers['Authorization'].split(' ')[1]
        if id_token is None:
            raise Exception('Could not find an ID token, request is not authenticated')

        jwt_token = jwt.decode(
            id_token,
            settings.SHOPIFY_API_SECRET,
            algorithms = ['HS256'],
            audience = settings.SHOPIFY_API_KEY
        )

        response = AuthResponse()
        response.shop = jwt_token['dest'].replace('https://', '')
        response.access_token = self.__token_exchange(id_token, response.shop, jwt_token['sub'])
        response.id_token = id_token

        return response


    def __token_exchange(self, id_token, shop, user):
        # We strongly recommend caching access tokens to make your app faster
        cache_key = f'{shop}_{user}' if settings.ONLINE_TOKENS else shop
        cached_token = cache.get(cache_key)
        if cached_token is not None:
            return cached_token

        client = OAuth2Session(
            settings.SHOPIFY_API_KEY,
            settings.SHOPIFY_API_SECRET,
        )

        if settings.ONLINE_TOKENS:
            token_type = 'urn:shopify:params:oauth:token-type:online-access-token'
        else:
            token_type = 'urn:shopify:params:oauth:token-type:offline-access-token'

        token = client.fetch_token(
            f'https://{shop}/admin/oauth/access_token',
            **{
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'subject_token': id_token,
                'requested_token_type': token_type,
            }
        )

        cache.set(cache_key, token['access_token'], 24 * 3600)

        return token['access_token']


    def __set_csp_headers(self, request, response):
        if request.headers.get('Sec-Fetch-Dest') != 'iframe':
            return

        header = response.headers.get('Content-Security-Policy')
        header = [header] if header is not None else []
        header.append(f"frame-ancestors https://{request.shop} https://admin.shopify.com")

        response.headers['Content-Security-Policy'] = '; '.join(header)


    def __sanitize_shop(self, shop):
        shop_regex = r'^[a-zA-Z0-9][a-zA-Z0-9_-]*\.myshopify\.com$'
        if not re.match(shop_regex, shop):
            raise ValueError('Invalid shop format')
        return shop
