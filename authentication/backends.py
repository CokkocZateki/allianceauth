from django.contrib.auth.models import User

from eveonline.models import EveCharacter


class EvESsoBackend(object):
    def authenticate(self, character_id=None, character_name=None):
        try:
            eve_character = EveCharacter.objects.get(character_id=character_id)
            return eve_character.user
        except EveCharacter.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
