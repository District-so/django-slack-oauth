# -*- coding: utf-8 -*-

import uuid
from importlib import import_module

import requests

import django
from django.contrib import messages

DJANGO_MAJOR_VERSION =  int(django.__version__.split('.')[0])
if DJANGO_MAJOR_VERSION < 2:
    from django.core.urlresolvers import reverse
else:
    from django.urls import reverse

from django.http.response import HttpResponseRedirect, HttpResponse
from django.views.generic import RedirectView, View

from . import settings

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

__all__ = (
    'SlackAuthView',
    'DefaultSuccessView'
)


class StateMismatch(Exception):
    pass


class DefaultSuccessView(View):
    def get(self, request):
        messages.success(request, "You've been successfully authenticated.")
        return HttpResponse("Slack OAuth login successful.")


class SlackAuthView(RedirectView):
    permanent = True

    text_error = 'Attempt to update has failed. Please try again.'

    def get(self, request, *args, **kwargs):
        code = request.GET.get('code')
        data = request.GET.get('data')
        redirect_uri = request.GET.get('redirect_uri')
        if not code:
            return self.auth_request(data, redirect_uri)

        data, redirect_uri = self.validate_state(request.GET.get('state'))

        access_content = self.oauth_access(code)
        if not access_content.status_code == 200:
            return self.error_message()

        api_data = access_content.json()
        api_data['data'] = data
        if not api_data['ok']:
            return self.error_message(api_data['error'])

        pipelines = settings.SLACK_PIPELINES

        # pipelines is a list of the callables to be executed
        pipelines = [getattr(import_module('.'.join(p.split('.')[:-1])), p.split('.')[-1]) for p in pipelines]
        return self.execute_pipelines(request, api_data, pipelines, redirect_uri)

    def execute_pipelines(self, request, api_data, pipelines, redirect_uri):
        if len(pipelines) == 0:
            # Terminate at the successful redirect
            if redirect_uri:
                return self.response(redirect=redirect_uri)
            return self.response()
        else:
            # Call the next function in the queue
            request, api_data = pipelines.pop(0)(request, api_data)
            return self.execute_pipelines(request, api_data, pipelines, redirect_uri)

    def auth_request(self, data, redirect_uri):
        state = self.store_state(data)
        self.store_redirect_uri(redirect_uri)

        params = urlencode({
            'client_id': settings.SLACK_CLIENT_ID,
            'redirect_uri': self.request.build_absolute_uri(reverse('slack_auth')),
            'scope': settings.SLACK_SCOPE,
            'state': state,
        })

        return self.response(settings.SLACK_AUTHORIZATION_URL + '?' + params)

    def oauth_access(self, code):
        params = {
            'client_id': settings.SLACK_CLIENT_ID,
            'client_secret': settings.SLACK_CLIENT_SECRET,
            'code': code,
            'redirect_uri': self.request.build_absolute_uri(reverse('slack_auth')),
        }

        return requests.get(settings.SLACK_OAUTH_ACCESS_URL, params=params)

    def validate_state(self, state):
        state_before = self.request.session.pop('state')
        if state_before != state:
            raise StateMismatch('State mismatch upon authorization completion.'
                                ' Try new request.')
        data = state.split(':')
        redirect_uri = self.request.session.pop('redirect_uri')
        return data[1] if len(data) > 1 else None, redirect_uri

    def store_state(self, data):
        state = str(uuid.uuid4())[:6]
        if data:
            state += ':' + data
        self.request.session['state'] = state
        return state

    def store_redirect_uri(self, redirect_uri):
        if not redirect_uri:
            self.request.session['redirect_uri'] = redirect_uri
        return redirect_uri

    def error_message(self, msg=text_error):
        messages.add_message(self.request, messages.ERROR, '%s' % msg)
        return self.response(redirect=settings.SLACK_ERROR_REDIRECT_URL)

    def response(self, redirect=settings.SLACK_SUCCESS_REDIRECT_URL):
        return HttpResponseRedirect(redirect)
