class ClamAVException(Exception):
    """Base ClamAV Exception."""


class ClamAVConnectException(ClamAVException):
    """Error while connecting to clamd."""


class ClamAVSizeExceeded(ClamAVException):
    """File size exceeded exception."""


class ClamAVNoStatusException(ClamAVException):
    """No status received from clamd."""


class ClamAVSendException(ClamAVException):
    """Error while sending data to clamd."""


class ClamAVTimeoutException(ClamAVException):
    """Timeout Exception"""


class ClamAVResponseException(ClamAVException):
    """Error while receiving response from clamd."""
