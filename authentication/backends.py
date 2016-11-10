import re

from django.contrib.auth.models import User

from eveonline.models import EveCharacter


class EvESsoBackend(object):
    def authenticate(self, character_id=None, character_name=None, character_owner_hash=None):
        try:
            eve_character = EveCharacter.objects.get(character_id=character_id)
            return eve_character.user
        except EveCharacter.DoesNotExist:
            try:
                user = User.objects.get(username=character_owner_hash)
            except User.DoesNotExist:
                user = User.objects.create_user(username=character_owner_hash, password=character_owner_hash)
                user.first_name = character_name
                user.save()
            return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
