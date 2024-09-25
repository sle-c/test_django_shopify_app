import base64
import hashlib
import hmac
import json
import logging
import re

from django.conf import settings
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect, QueryDict
from django.utils.decorators import decorator_from_middleware
from django.views.decorators.csrf import csrf_exempt
from authlib.integrations.requests_client import OAuth2Session
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport, TransportServerError, log
log.setLevel(logging.WARNING)

from app.middleware.auth import AuthMiddleware


@decorator_from_middleware(AuthMiddleware)
def index(request, page="index"):
    return render(
        request,
        f"{page}.html",
        {
            'embedded': settings.EMBEDDED,
            'api_key': settings.SHOPIFY_API_KEY,
        }
    )


@decorator_from_middleware(AuthMiddleware)
def data(request):
    shop = request.shop
    access_token = request.access_token

    transport = AIOHTTPTransport(
        url = f'https://{shop}/admin/api/{settings.API_VERSION}/graphql.json',
        headers = {'X-Shopify-Access-Token': access_token}
    )

    client = Client(transport=transport, fetch_schema_from_transport=True)

    query = gql("""
        query shopName {
            shop {
                name
            }
        }"""
    )

    try:
        result = client.execute(query)
    except TransportServerError as e:
        if e.code == 401:
            return HttpResponse(
                status=401
            )
        raise e

    return HttpResponse(
        json.dumps({'data': result}),
        content_type='application/json',
    )


@csrf_exempt
def webhooks(request):
    hmac_header = request.headers['X-Shopify-Hmac-Sha256']
    data = request.body

    if not hmac_header or not data:
        return HttpResponseBadRequest('Invalid request')

    expected_hmac = base64.b64encode(hmac.new(
        settings.SHOPIFY_API_SECRET.encode('utf-8'),
        data,
        hashlib.sha256
    ).digest()).decode()

    if not __safe_str_compare(hmac_header, expected_hmac):
        return HttpResponseBadRequest('Invalid HMAC')

    logging.info(f'Received webhook for topic \'{request.headers["X-Shopify-Topic"]}\'')
    return HttpResponse()


def login(request):
    shop = __sanitize_shop(request.GET['shop'])

    client = OAuth2Session(
        settings.SHOPIFY_API_KEY,
        settings.SHOPIFY_API_SECRET,
        scope=settings.SCOPES,
        redirect_uri=f'{settings.SHOPIFY_APP_URL}/auth/callback',
        **{'grant_options[]': 'per-user' if settings.ONLINE_TOKENS else ''},
    )

    uri, state = client.create_authorization_url(
        f'https://{shop}/admin/oauth/authorize'
    )

    response = HttpResponseRedirect(uri)
    response.set_cookie('state', state)
    print(uri)
    return response


def callback(request):
    if not __safe_str_compare(request.GET['hmac'], __build_hmac(request)):
        raise Exception('HMAC validation failed')

    shop = __sanitize_shop(request.GET['shop'])
    state = request.COOKIES.get('state')

    client = OAuth2Session(
        settings.SHOPIFY_API_KEY,
        settings.SHOPIFY_API_SECRET,
        state=state,
    )

    token = client.fetch_token(
        f'https://{shop}/admin/oauth/access_token',
        authorization_response=request.build_absolute_uri()
    )

    request.session['shop'] = shop
    request.session['access_token'] = token['access_token']

    response = HttpResponseRedirect('/')
    response.delete_cookie('state')
    return response


def __build_hmac(request):
    query = QueryDict(request.GET.urlencode(), mutable=True)
    del query['hmac']

    expected_hmac = hmac.new(
        settings.SHOPIFY_API_SECRET.encode('utf-8'),
        query.urlencode().encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return expected_hmac


def __sanitize_shop(shop):
    shop_regex = r'^[a-zA-Z0-9][a-zA-Z0-9_-]*\.myshopify\.com$'
    if not re.match(shop_regex, shop):
        raise ValueError('Invalid shop format')
    return shop


def __safe_str_compare(s1, s2):
    if len(s1) != len(s2):
        return False

    for a, b in zip(s1, s2):
        if a != b:
            return False

    return True
