#!/usr/bin/env python3
"""Probe the user supplied OpenAI compatible endpoint without recording secrets."""
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def main():
    key = os.environ.get('API_KEY', '')
    base = os.environ.get('BASE_URL', '').rstrip('/')
    model = os.environ.get('MODEL', '')
    if not all((key, base, model)):
        raise SystemExit('API_KEY, BASE_URL and MODEL must be set')
    result = {'schema': 1, 'model': model,
              'endpoint_sha256': hashlib.sha256(base.encode()).hexdigest()}
    payload = json.dumps({'model': model,
                          'messages': [{'role': 'user', 'content': 'Reply with OK.'}],
                          'max_tokens': 16}).encode()
    request = urllib.request.Request(
        base + '/chat/completions', data=payload,
        headers={'Authorization': 'Bearer ' + key,
                 'Content-Type': 'application/json'}, method='POST')
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = json.load(response)
            result['http_status'] = response.status
            result['response_model'] = body.get('model', '')
            result['usage'] = body.get('usage', {})
            result['content_present'] = bool(body.get('choices', [{}])[0].get('message', {}).get('content'))
            result['status'] = 'ok'
    except urllib.error.HTTPError as error:
        result.update(status='http_error', http_status=error.code)
        try:
            body = json.loads(error.read(65536))
            result['error_type'] = body.get('error', {}).get('type', '')
            result['error_code'] = body.get('error', {}).get('code', '')
        except (ValueError, AttributeError):
            pass
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        result.update(status='transport_error', error_type=type(error).__name__)
    result['elapsed_seconds'] = round(time.monotonic() - started, 3)
    out = Path('results/pbfuzz/api-probe.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True))
    if result['status'] != 'ok':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
