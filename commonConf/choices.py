from abc import ABC, abstractmethod

class Choices(ABC):
    """
    Base class for choices, which are used in model fields.
    """

    @classmethod
    @abstractmethod
    def choices(cls):
        """
        Return list of tuples with value and human-readable string.
        """
        pass

    @classmethod
    def choices_as_dicts(cls, only=None):
        """
        Return list of choices, where choice is a dict with value and display_value keys.
        """
        return [
            {'value': value, 'display_value': display_value}
            for value, display_value in cls.choices() if only is None or value in only
        ]

    @classmethod
    def get_display(cls, value):
        """
        Return human-readable string for choice as defined in choices.
        """
        return dict(cls.choices()).get(value)

class SocialChoices(Choices):
    FACEBOOK = 'facebook'
    INSTAGRAM = 'instagram'
    GOOGLE = 'google'
    TWITTER = 'twitter'

    @classmethod
    def choices(cls):
        return (
            (cls.FACEBOOK, 'Facebook'),
            (cls.INSTAGRAM, 'Instagram'),
            (cls.GOOGLE, 'Google'),
            (cls.TWITTER, 'Twitter'),
        )
        
class UserChoices(Choices):
    OTHER = 'other'
    @classmethod
    def choices(cls):
        return (
            (cls.OTHER, 'Other'),
        )