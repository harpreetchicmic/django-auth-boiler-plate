from django.conf import settings
class aRequest:
    request : {} 

    def get_image_path_insert(self, url):
        return url.replace(settings.BASE_URL,'')

    def get_image_path(self, url):
        if isinstance(url,str):
            if  "http" ==  url[0:4]:
                return url
            else:
                return settings.BASE_URL + url
        else: 
            return ""        