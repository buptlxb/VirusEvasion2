# -*- coding: utf-8 -*-


class VEException(Exception):
    """Base exception class."""
    pass


class PEFormatError(VEException):
    """Raised when an invalid field on the PE instance was found."""
    pass
