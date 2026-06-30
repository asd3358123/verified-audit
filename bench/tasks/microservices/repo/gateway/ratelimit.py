_HITS = {}


def client_key(request):
    return request["headers"].get("X-Forwarded-For", request["remote_addr"])


def allow(request, limit=100):
    key = client_key(request)
    _HITS[key] = _HITS.get(key, 0) + 1
    return _HITS[key] <= limit
