import asyncio
import os
from typing import List

class ScreenshotCollector:
    def __init__(self, output_dir: str, threads: int = 5):
        self.output_dir = output_dir
        self.threads = threads
        self.screenshots: List[str] = []

    async def capture(self, urls: List[str]) -> List[str]:
        os.makedirs(self.output_dir, exist_ok=True)
        semaphore = asyncio.Semaphore(self.threads)
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            print("[!] playwright not installed. Run: pip install playwright && playwright install chromium")
            return []
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(viewport={"width": 1280, "height": 720}, user_agent="Mozilla/5.0")
            async def _cap(url: str):
                async with semaphore:
                    try:
                        filename = url.replace("://", "_").replace("/", "_").replace(":", "_")[:100]
                        path = os.path.join(self.output_dir, f"{filename}.png")
                        page = await context.new_page()
                        await page.goto(url, timeout=30000, wait_until="domcontentloaded")
                        await page.screenshot(path=path, full_page=False)
                        await page.close()
                        self.screenshots.append(path)
                    except: pass
            await asyncio.gather(*[_cap(u) for u in urls], return_exceptions=True)
            await browser.close()
        print(f"[\\u2713] Captured {len(self.screenshots)} screenshots to {self.output_dir}")
        return self.screenshots
