from rest_framework.response import Response
def api_response(message, success_status, response_status, dict=None):
    if dict == None:
        dict = {}
        dict['message'] = message
        dict['status'] = success_status
    return Response(dict, status=response_status)

regex = r'\b^(([^<>()\\.,;:\s@"]+(\.[^<>()\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$\b'