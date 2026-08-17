"""web_requests.py — TRAINING fixture (intentionally vulnerable, teacher-labeled).

SSRF (CWE-918), XXE (CWE-611), and reflected XSS (CWE-79) patterns for the S5
corpus.
"""

import urllib.request

import requests
from lxml import etree


def fetch_url(url):
    return requests.get(url).text


def proxy_request(target):
    return urllib.request.urlopen(target).read()


def load_avatar(image_url):
    resp = requests.get(image_url, allow_redirects=True)
    return resp.content


def parse_xml(data):
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    return etree.fromstring(data, parser)


def load_config_xml(path):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.parse(path, parser)


def render_greeting(name):
    return f"<h1>Welcome back, {name}!</h1>"


def show_comment(comment):
    return "<div class='comment'>" + comment + "</div>"


def search_results(query):
    return f"<p>Results for <b>{query}</b></p>"
