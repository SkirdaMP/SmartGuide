import json

from rauth import OAuth2Service
from flask import current_app, url_for, request, redirect, session


class OAuthSignIn:
    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'].get(provider_name)
        if credentials != None:
            self.consumer_id = credentials.get('id')
            self.consumer_secret = credentials.get('secret')

    def authorize(self):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('oauth_callback', provider=self.provider_name,
                       _external=True)

    @classmethod
    def get_provider(self, provider_name):
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
            return self.providers[provider_name]
        else:
            return self.providers[provider_name]


class YandexSignIn(OAuthSignIn):
    def __init__(self):
        super(YandexSignIn, self).__init__('yandex')
        self.service = OAuth2Service(
            name='yandex',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://oauth.yandex.ru/authorize',
            access_token_url='https://oauth.yandex.ru/token',
            base_url='https://oauth.yandex.ru/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            response_type='code',
        ))

    def callback(self):
        def decode_json(payload):
            return json.loads(payload.decode('utf-8'))

        if 'code' not in request.args:
            return None
        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code'},
            decoder=decode_json
        )
        print(type(oauth_session), oauth_session)
        return oauth_session.access_token
