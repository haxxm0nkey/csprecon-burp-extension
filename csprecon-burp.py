"""
CSP Recon by @haxxm0nkey 

Good luck and good hunting!
"""

from burp import IBurpExtender, IHttpListener, IScanIssue
from java.io import PrintWriter
import re
import hashlib

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # Configuration
        self.DEBUG = False
        self._unique_csps = set()

        # Register extension
        callbacks.setExtensionName("CSP Recon")
        callbacks.registerHttpListener(self)

        self._stdout.println("CSP Recon 0.0.1 by @haxxm0nkey")

    def debug_print(self, message):
        """Print debug messages if DEBUG is enabled."""
        if self.DEBUG:
            self._stdout.println(message)

    def get_content_hash(self, domains, urls, report_uris):
        """Create a hash of the CSP content for deduplication."""
        content = (
            "|".join(sorted(domains)) + 
            "|".join(sorted(urls)) + 
            "|".join(sorted(report_uris))
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def format_bullet_list(self, items):
        """Format items as an HTML unordered list."""
        if not items:
            return "None found"
        return "<ul>\n" + "\n".join("<li>{}</li>".format(item) for item in sorted(items)) + "\n</ul>"

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Intercept HTTP responses and analyze CSP headers in real-time."""
        if messageIsRequest:
            return

        try:
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            self.debug_print("[DEBUG] Scanning URL: {}".format(url))

            response = messageInfo.getResponse()
            if not response:
                return

            analyzed = self._helpers.analyzeResponse(response)
            headers = analyzed.getHeaders()

            # Extract CSP headers
            csp_headers = [h for h in headers if "content-security-policy" in h.lower()]
            if not csp_headers:
                return

            domains, urls, report_uris = set(), set(), set()

            for header in csp_headers:
                try:
                    csp_value = header.split(':', 1)[1].strip()

                    # Extract report-uri
                    report_uri_match = re.search(r'report-uri\s+([^;]+)', csp_value, re.IGNORECASE)
                    if report_uri_match:
                        report_uris.add(report_uri_match.group(1).strip())

                    # Extract domains
                    domain_pattern = r'[\w\-\*]+\.[\w\-\.]+\w+'
                    domains.update(re.findall(domain_pattern, csp_value))

                    # Extract URLs
                    url_pattern = r'https?://[^\s\'"]+'
                    urls.update(re.findall(url_pattern, csp_value))

                except Exception as e:
                    self.debug_print("[DEBUG] Error processing CSP header: {}".format(str(e)))

            # Deduplication based on CSP content hash
            content_hash = self.get_content_hash(domains, urls, report_uris)
            if content_hash in self._unique_csps:
                return 

            self._unique_csps.add(content_hash)  # Mark this CSP as reported

            # Report issues
            if domains:
                self._callbacks.addScanIssue(CustomScanIssue(
                    messageInfo.getHttpService(),
                    url,
                    [messageInfo],
                    "[CSP Recon] Domains",
                    "The following domains were found in Content-Security-Policy headers:<br>" +
                    self.format_bullet_list(domains),
                    "Information"
                ))

            if urls:
                self._callbacks.addScanIssue(CustomScanIssue(
                    messageInfo.getHttpService(),
                    url,
                    [messageInfo],
                    "[CSP Recon] URLs",
                    "The following URLs were found in Content-Security-Policy headers:<br>" +
                    self.format_bullet_list(urls),
                    "Information"
                ))

            if report_uris:
                self._callbacks.addScanIssue(CustomScanIssue(
                    messageInfo.getHttpService(),
                    url,
                    [messageInfo],
                    "[CSP Recon] Report URIs",
                    "The following report URIs were found in Content-Security-Policy headers:<br>" +
                    self.format_bullet_list(report_uris),
                    "Information"
                ))

        except Exception as e:
            self.debug_print("[DEBUG] Error in processHttpMessage: {}".format(str(e)))

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
