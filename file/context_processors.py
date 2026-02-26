def user_role(request):
    if request.user.is_authenticated:
        return {'is_admin': request.user.role == 'admin'}
    return {'is_admin': False}
