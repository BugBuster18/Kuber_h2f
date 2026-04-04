"""
CVE Enrichment Service for KubeAttackViz.

Queries the NIST NVD API v2.0 to fetch live CVSS scores for CVEs.
Includes local caching to ensure speed and bypass rate limits.
"""

import json
import os
import time
import requests
from pathlib import Path
from typing import Dict, Optional
from rich.console import Console

console = Console()

class CVEEnricher:
    def __init__(self, cache_file: str = ".cve_cache.json"):
        self.cache_path = Path(cache_file)
        self.cache: Dict[str, float] = self._load_cache()
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = os.getenv("NVD_API_KEY") # Optional
        
    def _load_cache(self) -> Dict[str, float]:
        if self.cache_path.exists():
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_cache(self):
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(self.cache, f, indent=2)

    def get_cvss(self, cve_id: str) -> Optional[float]:
        """Fetch CVSS score for a CVE, checking cache first."""
        if not cve_id or not cve_id.startswith("CVE-"):
            return None
            
        if cve_id in self.cache:
            return self.cache[cve_id]

        try:
            # Query NVD API v2.0
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
                
            params = {"cveId": cve_id}
            
            # Rate limit avoidance (unauthenticated NVD API requires 6s between requests)
            if not self.api_key:
                time.sleep(1.0) # Conservative wait

            response = requests.get(self.api_url, params=params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                if vulnerabilities:
                    metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
                    # Try CVSS v3.1, then v3.0, then v2.0
                    cvss_data = None
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData")
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0].get("cvssData")
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0].get("cvssData")
                        
                    if cvss_data:
                        score = float(cvss_data.get("baseScore", 0.0))
                        self.cache[cve_id] = score
                        self._save_cache()
                        return score

            return None
        except Exception as e:
            console.print(f"[dim yellow]Warning: Could not enrich {cve_id} via NVD: {e}[/]")
            return None

    def discover_cves_for_image(self, image_str: str) -> list[Dict]:
        """Search NVD API for CVEs associated with an image/version string.
        
        Example input: 'nginx:1.19.1'
        Example output: [{'id': 'CVE-2021-...', 'cvss': 7.5}, ...]
        """
        if not image_str or ":" not in image_str:
            return []
            
        # Check cache if we've searched this image before
        cache_key = f"IMGSEARCH:{image_str}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            # Format image string for keyword search (nginx:1.19 -> "nginx 1.19")
            keyword = image_str.replace(":", " ").replace("/", " ")
            params = {"keywordSearch": keyword}
            headers = {"apiKey": self.api_key} if self.api_key else {}
            
            if not self.api_key:
                time.sleep(1.0) # Rate limit protection

            response = requests.get(self.api_url, params=params, headers=headers, timeout=12)
            discovered = []

            if response.status_code == 200:
                data = response.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id")
                    
                    # Extract Score
                    metrics = cve.get("metrics", {})
                    cvss = 0.0
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV30" in metrics:
                        cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

                    discovered.append({"id": cve_id, "cvss": cvss})

            # Cache the list (limited to top 5 to avoid bloating graph)
            discovered = sorted(discovered, key=lambda x: x["cvss"], reverse=True)[:5]
            self.cache[cache_key] = discovered
            self._save_cache()
            return discovered

        except Exception as e:
            console.print(f"[dim yellow]Warning: Image discovery failed for {image_str}: {e}[/]")
            return []

# Singleton instance
enricher = CVEEnricher()
