import logging
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

class BrokenPipeMiddleware(MiddlewareMixin):
    """
    Middleware to handle broken pipe errors gracefully.
    These errors commonly occur during file uploads when the client disconnects.
    """
    
    def process_exception(self, request, exception):
        """
        Handle broken pipe and connection reset errors
        """
        if isinstance(exception, (BrokenPipeError, ConnectionResetError)):
            # Log the error but don't propagate it
            logger.warning(
                f"Broken pipe/connection reset from {self.get_client_ip(request)} "
                f"during {request.method} {request.path}. "
                f"Client likely disconnected during upload."
            )
            # Return None to suppress the error
            return None
            
        # For IOErrors that might be related to connection issues
        if isinstance(exception, IOError) and 'Broken pipe' in str(exception):
            logger.warning(
                f"IO error (broken pipe) from {self.get_client_ip(request)} "
                f"during {request.method} {request.path}"
            )
            return None
            
        # Let other exceptions propagate normally
        return None
    
    def get_client_ip(self, request):
        """Get the client's IP address from the request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip