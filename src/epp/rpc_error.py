import logging

#------------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------

class EPPError(Exception):
    code = -1
    message = 'Unknown error'

    def __init__(self, message='', code=-1, response=None, *args, **kwargs):
        if response:
            self.code = response['epp']['response']['result']['@code']
            if not self.message:
                self.message = response['epp']['response']['result']['msg']
        if int(code) > 0:
            self.code = code
        if message:
            self.message = message
        super(EPPError).__init__(*args, **kwargs)

    def __str__(self):
        return '[%s] %s' % (self.code, self.message)

#------------------------------------------------------------------------------

class EPPConnectionFailed(EPPError):
    pass


class EPPResponseFailed(EPPError):
    pass


class EPPResponseEmpty(EPPError):
    pass


class EPPBadResponse(EPPError):
    pass


class EPPUnexpectedResponse(EPPError):
    pass

#------------------------------------------------------------------------------
# following exceptions are raised based on EPP response code


class EPPCommandUseError(EPPError):
    code = 2002


class EPPRequiredParameterMissing(EPPError):
    code = 2003


class EPPObjectExists(EPPError):
    code = 2302


class EPPObjectNotExist(EPPError):
    code = 2303


class EPPObjectStatusProhibitsOperation(EPPError):
    code = 2304


class EPPAuthorizationError(EPPError):
    code = 2201


class EPPCommandFailed(EPPError):
    code = 2400


#------------------------------------------------------------------------------

def exception_from_response(response, message=None, code=None):
    try:
        code = code or response['epp']['response']['result']['@code']
        code = int(code)
    except:
        return EPPBadResponse(response=response, message=message)
    try:
        message = message or response['epp']['response']['result']['msg']
    except:
        return EPPBadResponse(response=response)
    if code == 2002:
        return EPPCommandUseError(response=response, message=message)
    elif code == 2003:
        return EPPRequiredParameterMissing(response=response, message=message)
    elif code == 2201:
        return EPPAuthorizationError(response=response, message=message)
    elif code == 2302:
        return EPPObjectExists(response=response, message=message)
    elif code == 2303:
        return EPPObjectNotExist(response=response, message=message)
    elif code == 2304:
        return EPPObjectStatusProhibitsOperation(response=response, message=message)
    elif code == 2400:
        return EPPCommandFailed(response=response, message=message)
    # TODO: other exceptions to be added here
    logger.warn('response code %r do not have mapped exception yet', code)
    return EPPUnexpectedResponse(response=response, message=message, code=code) 
