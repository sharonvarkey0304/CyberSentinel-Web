"""
crawler.py
-----------
Discovers pages within the same host.

Why:
- Automated scanners must first discover attack surface
- Limited depth prevents DoS-style crawling
"""

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(client, start_url, max_pages=30):
    visited = set()
    queue = [start_url]
    pages = []

    base_host = urlparse(start_url).netloc

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue

        try:
            response = client.get(url)
            visited.add(url)

            soup = BeautifulSoup(response.text, "lxml")
            pages.append((url, soup))

            for a in soup.select("a[href]"):
                next_url = urljoin(url, a["href"])
                if urlparse(next_url).netloc == base_host:
                    queue.append(next_url)

        except Exception:
            continue

    return pages
