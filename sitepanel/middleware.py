class CustomMiddleware(object):
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        """
        Code to be executed for each request BEFORE the view (and later middleware) are called.
        """
        
        print("Hello from Custom Middleware")

        response = self.get_response(request)

        """
        Code to be executed for each request AFTER the view are called.
        """

        return response