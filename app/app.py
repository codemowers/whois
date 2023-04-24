#!/usr/bin/env python3
import os
import json
from cachetools import TTLCache
from datetime import datetime
from sanic import Sanic
from sanic.response import raw
from prometheus_client import Gauge
from sanic_prometheus import monitor
from whois.parser import PywhoisError
from whois import whois

MAXSIZE = int(os.getenv("MAXSIZE", "10000"))
TTL = int(os.getenv("TTL", "86400"))

cache = TTLCache(maxsize=MAXSIZE, ttl=TTL)

gauge_cache_record_count = Gauge("whois_cache_record_count",
    "Cache record count")


app = Sanic("whois")


class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return tuple(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)


def normalize(obj):
    if obj is None:
        return obj
    if isinstance(obj, list):
        return set([d.lower() for d in obj])
    elif isinstance(obj, str):
        return set([obj.lower()])
    else:
        raise NotImplementedError()


@app.get("/query/<q:str>")
async def query(request, q):
    result = cache.get(q)
    if not result:
        try:
            result = whois(q)
        except PywhoisError:
            result = {}
        result["name_servers"] = normalize(result.get("name_servers", []))
        result.pop("status", None)
        result.pop("domain_name", None)
        result = dict((k, v) for k, v in result.items() if v)
        cache[q] = result
    gauge_cache_record_count.set(len(cache))
    return raw(json.dumps(result, cls=JSONEncoder),
        content_type="application/json")


@app.get("/export")
async def export(request):
    return raw(json.dumps(dict(cache), cls=JSONEncoder),
        content_type="application/json")


if __name__ == "__main__":
    monitor(app).expose_endpoint()
    app.run(host="0.0.0.0", port=3005, single_process=True, motd=False)
