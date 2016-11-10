import logging

from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.contrib.auth import logout
from django.http import HttpResponseBadRequest
from django.http import HttpResponseForbidden
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext

from eveonline.EvESSO import EvESSO
from forms import LoginForm

logger = logging.getLogger(__name__)


def login_user(request):
    logger.debug("login_user called by user %s" % request.user)
    if request.method == 'POST':
        form = LoginForm(request.POST)
        logger.debug("Request of type POST, received form, valid: %s" % form.is_valid())
        if form.is_valid():
            user = authenticate(username=form.cleaned_data['username'], password=form.cleaned_data['password'])
            logger.debug("Authentication attempt with supplied credentials. Received user %s" % user)
            if user is not None:
                if user.is_active:
                    logger.info("Successful login attempt from user %s" % user)
                    login(request, user)
                    return HttpResponseRedirect("/dashboard/")
                else:
                    logger.info("Login attempt failed for user %s: user marked inactive." % user)
            else:
                logger.info("Failed login attempt: provided username %s" % form.cleaned_data['username'])

            return render_to_response('public/login.html', {'form': form, 'error': True},
                                      context_instance=RequestContext(request))
    else:
        logger.debug("Providing new login form.")
        form = LoginForm()

    return render_to_response('public/login.html', {'form': form}, context_instance=RequestContext(request))


def logout_user(request):
    logger.debug("logout_user called by user %s" % request.user)
    logoutUser = request.user
    logout(request)
    logger.info("Successful logout for user %s" % logoutUser)
    return HttpResponseRedirect("/")


def redirect_to_sso(request):
    eve_sso = EvESSO(request)
    eve_sso_redirect_uri = eve_sso.generate_redirect_uri(eve_sso.generate_state())
    if eve_sso_redirect_uri is not None:
        return HttpResponseRedirect(eve_sso_redirect_uri)

    return HttpResponseBadRequest('Could not process sso request.')


def login_sso(request):
    eve_sso = EvESSO(request)
    if eve_sso.has_valid_state() is False:
        return HttpResponseBadRequest('Could not authenticate, incorrect state parameter received')

    if eve_sso.verify_auth_code() is False:
        return HttpResponseBadRequest('EvE Auth Token could not be verified, please try again.')

    char_info = eve_sso.obtain_char_info()
    if char_info is False:
        return HttpResponseBadRequest('A problem occurred, while verifying your barer token.')

    if 'CharacterID' not in char_info:
        return HttpResponseBadRequest('No valid Character info could be found.')

    character_id = unicode(char_info['CharacterID'])
    character_name = char_info['CharacterName']

    user = authenticate(character_id=character_id, character_name=character_name)
    if user is not None:
        if user.is_active:
            logger.info("Successful login attempt from user %s" % user)
            login(request, user)
            return HttpResponseRedirect("/dashboard/")
        else:
            logger.info("Login attempt failed for user %s: user marked inactive." % user)
    else:
        logger.info("Failed login attempt: provided character_id %s" % character_id)

    return HttpResponseForbidden('There is currently no account with your character %s connected.' % character_name)
