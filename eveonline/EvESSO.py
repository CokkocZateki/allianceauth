+from django.utils.crypto import get_random_string
+from django.conf import settings
+
+import base64
+import requests
+
+
+class EvESSO:
+    eve_sso_client_id_key = 'ClientID'
+    eve_sso_secret_key_key = 'SecretKey'
+    eve_sso_callback_uri = 'CallbackURL'
+    eve_sso_state_key = 'EvESSOState'
+    eve_sso_auth_token = 'EvESSOAuthToken'
+    request = None
+
+    login_redirect_url = 'https://login.eveonline.com/oauth/authorize'
+    token_post_url = 'https://login.eveonline.com/oauth/token'
+    verify_get_url = 'https://login.eveonline.com/oauth/verify'
+
+    def __init__(self, request):
+        self.request = request
+
+    def has_valid_state(self):
+        if self.eve_sso_state_key not in self.request.session:
+            return False
+        eve_sso_state = self.request.session[self.eve_sso_state_key]
+        del self.request.session[self.eve_sso_state_key]
+        return 'state' in self.request.GET and self.request.GET['state'] == eve_sso_state
+
+    def generate_state(self):
+        eve_sso_state = get_random_string(length=32)
+        self.request.session[self.eve_sso_state_key] = eve_sso_state
+        return eve_sso_state
+
+    def generate_redirect_uri(self, state=None):
+        arguments = [self.login_redirect_url, '?response_type=code']
+        if EvESSO.setting_is_valid(self.eve_sso_client_id_key) is False:
+            return None
+        arguments.append('&client_id=%s' % settings.EVE_SSO[self.eve_sso_client_id_key])
+        if EvESSO.setting_is_valid(self.eve_sso_callback_uri) is False:
+            return None
+        arguments.append('&redirect_uri=%s' % settings.EVE_SSO[self.eve_sso_callback_uri])
+        if state is not None:
+            arguments.append('&state=%s' % state)
+
+        return ''.join(arguments)
+
+    def verify_auth_code(self):
+        if EvESSO.setting_is_valid(self.eve_sso_client_id_key) is False:
+            return None
+        if EvESSO.setting_is_valid(self.eve_sso_secret_key_key) is False:
+            return None
+
+        auth_params = (settings.EVE_SSO[self.eve_sso_client_id_key], settings.EVE_SSO[self.eve_sso_secret_key_key])
+        auth_binary_string = b'%s:%s' % auth_params
+        headers = {'Authorization': 'Basic %s' % base64.b64encode(auth_binary_string),
+                   'Content-Type': 'application/x-www-form-urlencoded'}
+        payload = {
+            'grant_type': 'authorization_code',
+            'code': self.request.GET['code']
+        }
+
+        response = requests.post(self.token_post_url, data=payload, headers=headers)
+        if response.status_code is 200:
+            json_decoded_response = response.json()
+            self.request.session[self.eve_sso_auth_token] = json_decoded_response['access_token']
+            return True
+
+        return False
+
+    def obtain_char_info(self):
+        if self.eve_sso_auth_token not in self.request.session:
+            return False
+        headers = {'Authorization': 'Bearer %s' % self.request.session[self.eve_sso_auth_token]}
+
+        response = requests.get(self.verify_get_url, headers=headers)
+        if response.status_code is 200:
+            return response.json()
+        return False
+
+    @staticmethod
+    def setting_is_valid(key):
+        if not hasattr(settings, 'EVE_SSO'):
+            return False
+        if key not in settings.EVE_SSO:
Add a comment to this line
+            return False
+        if settings.EVE_SSO[key] == '':
+            return False
+        return True
