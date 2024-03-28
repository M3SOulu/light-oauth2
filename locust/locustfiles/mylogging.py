from inspect import stack
__all__ = ['get__name__']


def get__name__():
    return stack()[1][3]