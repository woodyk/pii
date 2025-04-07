#!/usr/bin/env python3
#
# duckduckagain.py

import requests
from bs4 import BeautifulSoup
import urllib.parse as urlparse
import time

def duckduckgo_search_extract_alternative(keywords, num_results=5, sleep_time=1):
    """
    Perform a DuckDuckGo search and extract the cached text from the top results, or live text if cache is unavailable.

    Parameters:
    - keywords: A list of search terms or keywords.
    - num_results: The number of top results to retrieve for each keyword.
    - sleep_time: Time to wait between requests to avoid overloading servers.

    Returns:
    - results_dict: A dictionary with the keywords as keys and the cleaned extracted text as values.
    """

    def clean_text(text):
        """
        Clean text by removing extra whitespace and optionally other unwanted characters.
        """
        # Remove extra whitespace (spaces, newlines, tabs)
        text = ' '.join(text.split())
        return text

    def extract_text_from_url(url):
        """Extracts and returns cleaned text from the given URL."""
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                # Extract text from the paragraphs
                paragraphs = soup.find_all('p')
                raw_text = ' '.join([para.get_text() for para in paragraphs])
                cleaned_text = clean_text(raw_text)  # Clean the extracted text
                return cleaned_text
            else:
                return f"Failed to retrieve content from {url}"
        except requests.exceptions.RequestException as e:
            return f"Error accessing {url}: {str(e)}"

    def search_duckduckgo(query, max_results):
        """Searches DuckDuckGo and returns the top search result URLs."""
        search_url = f"https://duckduckgo.com/html/?q={query.replace(' ', '+')}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(search_url, headers=headers)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extract search result links and decode redirection URLs
        links = []
        for result in soup.find_all('a', class_='result__a', limit=max_results):
            href = result.get('href')
            # Decode the redirection URL
            parsed_url = urlparse.urlparse(href)
            query_params = urlparse.parse_qs(parsed_url.query)
            if 'uddg' in query_params:
                decoded_url = query_params['uddg'][0]
                links.append(decoded_url)

        return links

    def get_cached_url(url):
        """
        Try to retrieve a cached version of the URL from the Wayback Machine.
        """
        wayback_url = f"http://archive.org/wayback/available?url={url}"
        response = requests.get(wayback_url)
        if response.status_code == 200:
            data = response.json()
            if data.get('archived_snapshots'):
                closest_snapshot = data['archived_snapshots'].get('closest')
                if closest_snapshot:
                    cached_url = closest_snapshot.get('url')
                    return cached_url
        return None

    results_dict = {}

    for keyword in keywords:
        print(f"Searching for: {keyword}")
        results_dict[keyword] = []

        # Perform DuckDuckGo search
        search_results = search_duckduckgo(keyword, num_results)

        for url in search_results:
            print(f"Extracting from: {url}")
            # Check if there's a cached version of the site available
            cached_url = get_cached_url(url)
            if cached_url:
                print(f"Using cached version of: {url}")
                extracted_text = extract_text_from_url(cached_url)
            else:
                print(f"No cached version available, pulling live site: {url}")
                extracted_text = extract_text_from_url(url)

            results_dict[keyword].append({
                "url": url,
                "cached_url": cached_url if cached_url else "No cache available",
                "extracted_text": extracted_text
            })

            # Optional sleep to avoid overloading the servers
            time.sleep(sleep_time)

    return results_dict

# Example usage:
keywords = ["wadih khairallah"]
result = duckduckgo_search_extract_alternative(keywords, num_results=10)

# Print the results
for keyword, entries in result.items():
    print(f"\nKeyword: {keyword}")
    for entry in entries:
        print(f"URL: {entry['url']}")
        print(f"Cached URL: {entry['cached_url']}")
        print(f"Extracted Text: {entry['extracted_text']}...")  # Show first 500 chars

