import requests


def deliver(subscription, event):
    # subscription.url is provided by the user when they register a webhook
    resp = requests.post(subscription["url"], json=event, timeout=5)
    return {"status": resp.status_code}
