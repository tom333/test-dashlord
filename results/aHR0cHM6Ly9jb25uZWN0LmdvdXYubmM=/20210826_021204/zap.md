
# ZAP Scanning Report

Generated on Thu, 26 Aug 2021 02:02:45


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 4 |
| Low | 6 |
| Informational | 5 |

## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- | 
| Content Security Policy (CSP) Header Not Set | Medium | 4 | 
| Sub Resource Integrity Attribute Missing | Medium | 4 | 
| Vulnerable JS Library | Medium | 1 | 
| X-Frame-Options Header Not Set | Medium | 4 | 
| Cross-Domain JavaScript Source File Inclusion | Low | 4 | 
| Dangerous JS Functions | Low | 1 | 
| Incomplete or No Cache-control Header Set | Low | 4 | 
| Permissions Policy Header Not Set | Low | 7 | 
| Strict-Transport-Security Header Not Set | Low | 10 | 
| X-Content-Type-Options Header Missing | Low | 10 | 
| Base64 Disclosure | Informational | 5 | 
| Information Disclosure - Suspicious Comments | Informational | 2 | 
| Modern Web Application | Informational | 6 | 
| Storable and Cacheable Content | Informational | 10 | 
| Timestamp Disclosure - Unix | Informational | 7 | 

## Alert Detail


  
  
  
  
### Content Security Policy (CSP) Header Not Set
##### Medium (High)
  
  
  
  
#### Description
<p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.</p>
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  
  
Instances: 4
  
### Solution
<p>Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header, to achieve optimal browser support: "Content-Security-Policy" for Chrome 25+, Firefox 23+ and Safari 7+, "X-Content-Security-Policy" for Firefox 4.0+ and Internet Explorer 10+, and "X-WebKit-CSP" for Chrome 14+ and Safari 6+.</p>
  
### Reference
* https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
* https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
* http://www.w3.org/TR/CSP/
* http://w3c.github.io/webappsec/specs/content-security-policy/csp-specification.dev.html
* http://www.html5rocks.com/en/tutorials/security/content-security-policy/
* http://caniuse.com/#feat=contentsecuritypolicy
* http://content-security-policy.com/

  
#### CWE Id : 693
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Sub Resource Integrity Attribute Missing
##### Medium (High)
  
  
  
  
#### Description
<p>The integrity attribute is missing on a script or link tag served by an external server. The integrity tag prevents an attacker who have gained access to this server from injecting a malicious content. </p>
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
Instances: 4
  
### Solution
<p>Provide a valid integrity attribute to the tag.</p>
  
### Reference
* https://developer.mozilla.org/en/docs/Web/Security/Subresource_Integrity

  
#### CWE Id : 345
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Vulnerable JS Library
##### Medium (Medium)
  
  
  
  
#### Description
<p>The identified library jquery, version 3.3.1 is vulnerable.</p>
  
  
  
* URL: [https://connect.gouv.nc/scripts.fce457a0dee10873921a.js](https://connect.gouv.nc/scripts.fce457a0dee10873921a.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `{jquery:"3.3.1"`
  
  
  
  
Instances: 1
  
### Solution
<p>Please upgrade to the latest version of jquery.</p>
  
### Other information
<p>CVE-2020-11023</p><p>CVE-2020-11022</p><p>CVE-2019-11358</p><p></p>
  
### Reference
* https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/
* https://nvd.nist.gov/vuln/detail/CVE-2019-11358
* https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b
* https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
* 

  
#### CWE Id : 829
  
#### Source ID : 3

  
  
  
  
### X-Frame-Options Header Not Set
##### Medium (Medium)
  
  
  
  
#### Description
<p>X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.</p>
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
Instances: 4
  
### Solution
<p>Most modern Web browsers support the X-Frame-Options HTTP header. Ensure it's set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive. </p>
  
### Reference
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

  
#### CWE Id : 1021
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Cross-Domain JavaScript Source File Inclusion
##### Low (Medium)
  
  
  
  
#### Description
<p>The page includes one or more script files from a third-party domain.</p>
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://www.googletagmanager.com/gtag/js?id=UA-127581475-1`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://www.googletagmanager.com/gtag/js?id=UA-127581475-1`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://www.googletagmanager.com/gtag/js?id=UA-127581475-1`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://www.googletagmanager.com/gtag/js?id=UA-127581475-1`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
Instances: 4
  
### Solution
<p>Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.</p>
  
### Reference
* 

  
#### CWE Id : 829
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Dangerous JS Functions
##### Low (Low)
  
  
  
  
#### Description
<p>A dangerous JS function seems to be in use that would leave the site vulnerable.</p>
  
  
  
* URL: [https://connect.gouv.nc/scripts.fce457a0dee10873921a.js](https://connect.gouv.nc/scripts.fce457a0dee10873921a.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `Eval`
  
  
  
  
Instances: 1
  
### Solution
<p>See the references for security advice on the use of these functions.</p>
  
### Reference
* https://angular.io/guide/security

  
#### CWE Id : 749
  
#### Source ID : 3

  
  
  
  
### Incomplete or No Cache-control Header Set
##### Low (Medium)
  
  
  
  
#### Description
<p>The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content.</p>
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
Instances: 4
  
### Solution
<p>Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate.</p>
  
### Reference
* https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control

  
#### CWE Id : 525
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Permissions Policy Header Not Set
##### Low (Medium)
  
  
  
  
#### Description
<p>Permissions Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Permissions Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.</p>
  
  
  
* URL: [https://connect.gouv.nc/runtime.4e4723ca96d057732d50.js](https://connect.gouv.nc/runtime.4e4723ca96d057732d50.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js](https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/scripts.fce457a0dee10873921a.js](https://connect.gouv.nc/scripts.fce457a0dee10873921a.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
Instances: 7
  
### Solution
<p>Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header.</p>
  
### Reference
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy
* https://developers.google.com/web/updates/2018/06/feature-policy
* https://scotthelme.co.uk/a-new-security-header-feature-policy/
* https://w3c.github.io/webappsec-feature-policy/
* https://www.smashingmagazine.com/2018/12/feature-policy/

  
#### CWE Id : 693
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Strict-Transport-Security Header Not Set
##### Low (High)
  
  
  
  
#### Description
<p>HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.</p>
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js](https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/runtime.4e4723ca96d057732d50.js](https://connect.gouv.nc/runtime.4e4723ca96d057732d50.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/assets/icons/favicon/favicon-32x32.png](https://connect.gouv.nc/assets/icons/favicon/favicon-32x32.png)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/assets/icons/favicon/favicon-16x16.png](https://connect.gouv.nc/assets/icons/favicon/favicon-16x16.png)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/styles.240968b39e5ca33df439.css](https://connect.gouv.nc/styles.240968b39e5ca33df439.css)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/scripts.fce457a0dee10873921a.js](https://connect.gouv.nc/scripts.fce457a0dee10873921a.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  
  
Instances: 10
  
### Solution
<p>Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.</p>
  
### Reference
* https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
* https://owasp.org/www-community/Security_Headers
* http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
* http://caniuse.com/stricttransportsecurity
* http://tools.ietf.org/html/rfc6797

  
#### CWE Id : 319
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### X-Content-Type-Options Header Missing
##### Low (Medium)
  
  
  
  
#### Description
<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.</p>
  
  
  
* URL: [https://connect.gouv.nc/styles.240968b39e5ca33df439.css](https://connect.gouv.nc/styles.240968b39e5ca33df439.css)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://connect.gouv.nc/assets/icons/favicon/favicon-32x32.png](https://connect.gouv.nc/assets/icons/favicon/favicon-32x32.png)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://connect.gouv.nc/runtime.4e4723ca96d057732d50.js](https://connect.gouv.nc/runtime.4e4723ca96d057732d50.js)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://connect.gouv.nc/assets/icons/favicon/favicon-16x16.png](https://connect.gouv.nc/assets/icons/favicon/favicon-16x16.png)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://connect.gouv.nc/scripts.fce457a0dee10873921a.js](https://connect.gouv.nc/scripts.fce457a0dee10873921a.js)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js](https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
Instances: 10
  
### Solution
<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.</p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.</p>
  
### Other information
<p>This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.</p><p>At "High" threshold this scan rule will not alert on client or server error responses.</p>
  
### Reference
* http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx
* https://owasp.org/www-community/Security_Headers

  
#### CWE Id : 693
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Base64 Disclosure
##### Informational (Medium)
  
  
  
  
#### Description
<p>Base64 encoded data was disclosed by the application/web server. Note: in the interests of performance not all base64 strings in the response were analyzed individually, the entire response should be looked at by the analyst/security team/developer(s).</p>
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `UzD3kUSk2hvxc7fs2O1RviAToXgKa6I3HQtBxONGl7o`
  
  
  
  
* URL: [https://connect.gouv.nc/styles.240968b39e5ca33df439.css](https://connect.gouv.nc/styles.240968b39e5ca33df439.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `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`
  
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `UzD3kUSk2hvxc7fs2O1RviAToXgKa6I3HQtBxONGl7o`
  
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `UzD3kUSk2hvxc7fs2O1RviAToXgKa6I3HQtBxONGl7o`
  
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `UzD3kUSk2hvxc7fs2O1RviAToXgKa6I3HQtBxONGl7o`
  
  
  
  
Instances: 5
  
### Solution
<p>Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.</p>
  
### Other information
<p>S0��D��\x001b�s����Q� \x0013�x</p><p>k�7\x001d\x000bA��F��</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Low)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [https://connect.gouv.nc/scripts.fce457a0dee10873921a.js](https://connect.gouv.nc/scripts.fce457a0dee10873921a.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `username`
  
  
  
  
* URL: [https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js](https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `Select`
  
  
  
  
Instances: 2
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bUSERNAME\b and was detected in the element starting with: "!function(t,e){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=t.document?e(t,!0):function(", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Modern Web Application
##### Informational (Medium)
  
  
  
  
#### Description
<p>The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.</p>
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
* URL: [https://connect.gouv.nc/scripts.fce457a0dee10873921a.js](https://connect.gouv.nc/scripts.fce457a0dee10873921a.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id='"+I+"'></a>`
  
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
* URL: [https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js](https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script>`
  
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=UA-127581475-1"></script>`
  
  
  
  
Instances: 6
  
### Solution
<p>This is an informational alert and so no changes are required.</p>
  
### Other information
<p>No links have been found while there are scripts, which is an indication that this is a modern web application.</p>
  
### Reference
* 

  
#### Source ID : 3

  
  
  
  
### Storable and Cacheable Content
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users.  If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.</p>
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/assets/icons/favicon/favicon-16x16.png](https://connect.gouv.nc/assets/icons/favicon/favicon-16x16.png)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/scripts.fce457a0dee10873921a.js](https://connect.gouv.nc/scripts.fce457a0dee10873921a.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/styles.240968b39e5ca33df439.css](https://connect.gouv.nc/styles.240968b39e5ca33df439.css)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/runtime.4e4723ca96d057732d50.js](https://connect.gouv.nc/runtime.4e4723ca96d057732d50.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js](https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/assets/icons/favicon/favicon-32x32.png](https://connect.gouv.nc/assets/icons/favicon/favicon-32x32.png)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  
  
Instances: 10
  
### Solution
<p>Validate that the response does not contain sensitive, personal or user-specific information.  If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:</p><p>Cache-Control: no-cache, no-store, must-revalidate, private</p><p>Pragma: no-cache</p><p>Expires: 0</p><p>This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request. </p>
  
### Other information
<p>In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.</p>
  
### Reference
* https://tools.ietf.org/html/rfc7234
* https://tools.ietf.org/html/rfc7231
* http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234)

  
#### CWE Id : 524
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Timestamp Disclosure - Unix
##### Informational (Low)
  
  
  
  
#### Description
<p>A timestamp was disclosed by the application/web server - Unix</p>
  
  
  
* URL: [https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js](https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `2146823252`
  
  
  
  
* URL: [https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js](https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `94906265`
  
  
  
  
* URL: [https://connect.gouv.nc/](https://connect.gouv.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `127581475`
  
  
  
  
* URL: [https://connect.gouv.nc/sitemap.xml](https://connect.gouv.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `127581475`
  
  
  
  
* URL: [https://connect.gouv.nc/robots.txt](https://connect.gouv.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `127581475`
  
  
  
  
* URL: [https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js](https://connect.gouv.nc/polyfills.f5f5030b96cc79d1a457.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `62425156`
  
  
  
  
* URL: [https://connect.gouv.nc](https://connect.gouv.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `127581475`
  
  
  
  
Instances: 7
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>2146823252, which evaluates to: 2038-01-11 11:47:32</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3
