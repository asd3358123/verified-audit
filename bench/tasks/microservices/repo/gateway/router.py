def is_protected(path):
    return path.startswith("/admin")


def route(request):
    path = request["path"]
    if is_protected(path) and not request.get("is_admin"):
        return {"error": "forbidden", "code": 403}
    # paths like "/admin/../public/x" pass is_protected()==False but the
    # downstream file server later normalizes them back under /admin
    return {"handler": path}
