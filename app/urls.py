from django.urls import path

from . import views


urlpatterns = [
    # Renders the HTML with the UI
    path("", views.index),

    # Fetches data from the API
    path("data", views.data),

    # Validates webook requests
    path("webhooks", views.webhooks),

    # Non-embedded only: initiates the OAuth flow
    path("auth", views.login),

    # Non-embedded only: callback for the OAuth flow
    path("auth/callback", views.callback),

    # # Catch-all URL for additional pages
    path("<slug:page>", views.index),
]
