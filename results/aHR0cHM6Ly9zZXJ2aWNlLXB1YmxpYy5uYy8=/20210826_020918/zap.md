
# ZAP Scanning Report

Generated on Thu, 26 Aug 2021 01:58:35


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 4 |
| Low | 8 |
| Informational | 5 |

## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- | 
| Content Security Policy (CSP) Header Not Set | Medium | 11 | 
| Reverse Tabnabbing | Medium | 11 | 
| Source Code Disclosure - SQL | Medium | 1 | 
| X-Frame-Options Header Not Set | Medium | 2 | 
| Absence of Anti-CSRF Tokens | Low | 11 | 
| Cookie without SameSite Attribute | Low | 2 | 
| Cookie Without Secure Flag | Low | 2 | 
| Incomplete or No Cache-control Header Set | Low | 11 | 
| Information Disclosure - Debug Error Messages | Low | 1 | 
| Permissions Policy Header Not Set | Low | 7 | 
| Strict-Transport-Security Header Not Set | Low | 11 | 
| X-Content-Type-Options Header Missing | Low | 11 | 
| Base64 Disclosure | Informational | 11 | 
| Information Disclosure - Suspicious Comments | Informational | 11 | 
| Modern Web Application | Informational | 11 | 
| Storable and Cacheable Content | Informational | 5 | 
| Storable but Non-Cacheable Content | Informational | 6 | 

## Alert Detail


  
  
  
  
### Content Security Policy (CSP) Header Not Set
##### Medium (High)
  
  
  
  
#### Description
<p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.</p>
  
  
  
* URL: [https://service-public.nc/misc/*.jpg](https://service-public.nc/misc/*.jpg)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/modules/*.css](https://service-public.nc/modules/*.css)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.gif](https://service-public.nc/misc/*.gif)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.css$](https://service-public.nc/misc/*.css$)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.js$](https://service-public.nc/misc/*.js$)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.css](https://service-public.nc/misc/*.css)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/modules/*.css$](https://service-public.nc/modules/*.css$)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.js](https://service-public.nc/misc/*.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.jpeg](https://service-public.nc/misc/*.jpeg)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/](https://service-public.nc/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.png](https://service-public.nc/misc/*.png)
  
  
  * Method: `GET`
  
  
  
  
Instances: 11
  
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

  
  
  
  
### Reverse Tabnabbing
##### Medium (Medium)
  
  
  
  
#### Description
<p>At least one link on this page is vulnerable to Reverse tabnabbing as it uses a target attribute without using both of the "noopener" and "noreferrer" keywords in the "rel" attribute, which allows the target page to take control of this page.</p>
  
  
  
* URL: [https://service-public.nc/misc/*.js$](https://service-public.nc/misc/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.province-nord.nc" target="_blank"><img typeof="foaf:Image" src="https://service-public.nc/sites/default/files/styles/logo_partenaire/public/logo_partenaire/province-nord_0.jpg?itok=tKjMu0l7" width="120" height="90" alt="Province Nord" title="Province Nord" /></a>`
  
  
  
  
* URL: [https://service-public.nc/profiles/*.js$](https://service-public.nc/profiles/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.province-nord.nc" target="_blank"><img typeof="foaf:Image" src="https://service-public.nc/sites/default/files/styles/logo_partenaire/public/logo_partenaire/province-nord_0.jpg?itok=tKjMu0l7" width="120" height="90" alt="Province Nord" title="Province Nord" /></a>`
  
  
  
  
* URL: [https://service-public.nc/](https://service-public.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.province-nord.nc" target="_blank"><img typeof="foaf:Image" src="https://service-public.nc/sites/default/files/styles/logo_partenaire/public/logo_partenaire/province-nord_0.jpg?itok=tKjMu0l7" width="120" height="90" alt="Province Nord" title="Province Nord" /></a>`
  
  
  
  
* URL: [https://service-public.nc/themes/*.css$](https://service-public.nc/themes/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.province-nord.nc" target="_blank"><img typeof="foaf:Image" src="https://service-public.nc/sites/default/files/styles/logo_partenaire/public/logo_partenaire/province-nord_0.jpg?itok=tKjMu0l7" width="120" height="90" alt="Province Nord" title="Province Nord" /></a>`
  
  
  
  
* URL: [https://service-public.nc/themes/*.js$](https://service-public.nc/themes/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.province-nord.nc" target="_blank"><img typeof="foaf:Image" src="https://service-public.nc/sites/default/files/styles/logo_partenaire/public/logo_partenaire/province-nord_0.jpg?itok=tKjMu0l7" width="120" height="90" alt="Province Nord" title="Province Nord" /></a>`
  
  
  
  
* URL: [https://service-public.nc/misc/*.css$](https://service-public.nc/misc/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.province-nord.nc" target="_blank"><img typeof="foaf:Image" src="https://service-public.nc/sites/default/files/styles/logo_partenaire/public/logo_partenaire/province-nord_0.jpg?itok=tKjMu0l7" width="120" height="90" alt="Province Nord" title="Province Nord" /></a>`
  
  
  
  
* URL: [https://service-public.nc/modules/*.js$](https://service-public.nc/modules/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.province-nord.nc" target="_blank"><img typeof="foaf:Image" src="https://service-public.nc/sites/default/files/styles/logo_partenaire/public/logo_partenaire/province-nord_0.jpg?itok=tKjMu0l7" width="120" height="90" alt="Province Nord" title="Province Nord" /></a>`
  
  
  
  
* URL: [https://service-public.nc/misc/](https://service-public.nc/misc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.province-nord.nc" target="_blank"><img typeof="foaf:Image" src="https://service-public.nc/sites/default/files/styles/logo_partenaire/public/logo_partenaire/province-nord_0.jpg?itok=tKjMu0l7" width="120" height="90" alt="Province Nord" title="Province Nord" /></a>`
  
  
  
  
* URL: [https://service-public.nc/includes/](https://service-public.nc/includes/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.province-nord.nc" target="_blank"><img typeof="foaf:Image" src="https://service-public.nc/sites/default/files/styles/logo_partenaire/public/logo_partenaire/province-nord_0.jpg?itok=tKjMu0l7" width="120" height="90" alt="Province Nord" title="Province Nord" /></a>`
  
  
  
  
* URL: [https://service-public.nc/profiles/*.css$](https://service-public.nc/profiles/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.province-nord.nc" target="_blank"><img typeof="foaf:Image" src="https://service-public.nc/sites/default/files/styles/logo_partenaire/public/logo_partenaire/province-nord_0.jpg?itok=tKjMu0l7" width="120" height="90" alt="Province Nord" title="Province Nord" /></a>`
  
  
  
  
* URL: [https://service-public.nc/modules/*.css$](https://service-public.nc/modules/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.province-nord.nc" target="_blank"><img typeof="foaf:Image" src="https://service-public.nc/sites/default/files/styles/logo_partenaire/public/logo_partenaire/province-nord_0.jpg?itok=tKjMu0l7" width="120" height="90" alt="Province Nord" title="Province Nord" /></a>`
  
  
  
  
Instances: 11
  
### Solution
<p>Do not use a target attribute, or if you have to then also add the attribute: rel="noopener noreferrer".</p>
  
### Reference
* https://owasp.org/www-community/attacks/Reverse_Tabnabbing
* https://dev.to/ben/the-targetblank-vulnerability-by-example
* https://mathiasbynens.github.io/rel-noopener/
* https://medium.com/@jitbit/target-blank-the-most-underestimated-vulnerability-ever-96e328301f4c

  
#### Source ID : 3

  
  
  
  
### Source Code Disclosure - SQL
##### Medium (Medium)
  
  
  
  
#### Description
<p>Application Source Code was disclosed by the web server - SQL</p>
  
  
  
* URL: [https://service-public.nc/INSTALL.pgsql.txt](https://service-public.nc/INSTALL.pgsql.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `CREATE DATABASE USER`
  
  
  
  
Instances: 1
  
### Solution
<p>Ensure that application Source Code is not available with alternative extensions, and ensure that source code is not present within other files or data deployed to the web server, or served by the web server. </p>
  
### Other information
<p>CREATE DATABASE USER</p>
  
### Reference
* http://blogs.wsj.com/cio/2013/10/08/adobe-source-code-leak-is-bad-news-for-u-s-government/

  
#### CWE Id : 540
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### X-Frame-Options Header Not Set
##### Medium (Medium)
  
  
  
  
#### Description
<p>X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.</p>
  
  
  
* URL: [https://service-public.nc/xmlrpc.php](https://service-public.nc/xmlrpc.php)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://service-public.nc/install.php](https://service-public.nc/install.php)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
Instances: 2
  
### Solution
<p>Most modern Web browsers support the X-Frame-Options HTTP header. Ensure it's set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive. </p>
  
### Reference
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

  
#### CWE Id : 1021
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Absence of Anti-CSRF Tokens
##### Low (Medium)
  
  
  
  
#### Description
<p>No Anti-CSRF tokens were found in a HTML submission form.</p><p>A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.</p><p></p><p>CSRF attacks are effective in a number of situations, including:</p><p>    * The victim has an active session on the target site.</p><p>    * The victim is authenticated via HTTP auth on the target site.</p><p>    * The victim is on the same local network as the target site.</p><p></p><p>CSRF has primarily been used to perform an action against a target site using the victim's privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.</p>
  
  
  
* URL: [https://service-public.nc/themes/*.js$](https://service-public.nc/themes/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/themes/*.js$" method="post" id="search-block-form" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://service-public.nc/misc/*.css$](https://service-public.nc/misc/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/misc/*.css$" method="post" id="search-block-form" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://service-public.nc/themes/*.css$](https://service-public.nc/themes/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/themes/*.css$" method="post" id="search-block-form" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://service-public.nc/misc/*.js$](https://service-public.nc/misc/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/misc/*.js$" method="post" id="search-block-form" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://service-public.nc/modules/*.js$](https://service-public.nc/modules/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/modules/*.js$" method="post" id="search-block-form" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://service-public.nc/profiles/*.js$](https://service-public.nc/profiles/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/profiles/*.js$" method="post" id="search-block-form" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://service-public.nc/profiles/*.css$](https://service-public.nc/profiles/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/profiles/*.css$" method="post" id="search-block-form" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://service-public.nc/misc/](https://service-public.nc/misc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/misc/" method="post" id="search-block-form" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://service-public.nc/](https://service-public.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/" method="post" id="search-block-form" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://service-public.nc/modules/*.css$](https://service-public.nc/modules/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/modules/*.css$" method="post" id="search-block-form" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://service-public.nc/includes/](https://service-public.nc/includes/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/includes/" method="post" id="search-block-form" accept-charset="UTF-8">`
  
  
  
  
Instances: 11
  
### Solution
<p>Phase: Architecture and Design</p><p>Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.</p><p>For example, use anti-CSRF packages such as the OWASP CSRFGuard.</p><p></p><p>Phase: Implementation</p><p>Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.</p><p></p><p>Phase: Architecture and Design</p><p>Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Use the ESAPI Session Management control.</p><p>This control includes a component for CSRF.</p><p></p><p>Do not use the GET method for any request that triggers a state change.</p><p></p><p>Phase: Implementation</p><p>Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.</p>
  
### Other information
<p>No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF] was found in the following HTML form: [Form 1: "edit-search-block-form--2" "edit-submit" "form_build_id" "form_id" ].</p>
  
### Reference
* http://projects.webappsec.org/Cross-Site-Request-Forgery
* http://cwe.mitre.org/data/definitions/352.html

  
#### CWE Id : 352
  
#### WASC Id : 9
  
#### Source ID : 3

  
  
  
  
### Cookie without SameSite Attribute
##### Low (Medium)
  
  
  
  
#### Description
<p>A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.</p>
  
  
  
* URL: [https://service-public.nc/particuliers/sante-social/handicap](https://service-public.nc/particuliers/sante-social/handicap)
  
  
  * Method: `GET`
  
  
  * Parameter: `SESS3963c2b234b2db5bb7c5f8b1f641a1a2`
  
  
  * Evidence: `Set-Cookie: SESS3963c2b234b2db5bb7c5f8b1f641a1a2`
  
  
  
  
* URL: [https://service-public.nc/particuliers/sante-social/securite-sanitaire](https://service-public.nc/particuliers/sante-social/securite-sanitaire)
  
  
  * Method: `GET`
  
  
  * Parameter: `SESS3963c2b234b2db5bb7c5f8b1f641a1a2`
  
  
  * Evidence: `Set-Cookie: SESS3963c2b234b2db5bb7c5f8b1f641a1a2`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.</p>
  
### Reference
* https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site

  
#### CWE Id : 1275
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Cookie Without Secure Flag
##### Low (Medium)
  
  
  
  
#### Description
<p>A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections.</p>
  
  
  
* URL: [https://service-public.nc/particuliers/sante-social/securite-sanitaire](https://service-public.nc/particuliers/sante-social/securite-sanitaire)
  
  
  * Method: `GET`
  
  
  * Parameter: `SESS3963c2b234b2db5bb7c5f8b1f641a1a2`
  
  
  * Evidence: `Set-Cookie: SESS3963c2b234b2db5bb7c5f8b1f641a1a2`
  
  
  
  
* URL: [https://service-public.nc/particuliers/sante-social/handicap](https://service-public.nc/particuliers/sante-social/handicap)
  
  
  * Method: `GET`
  
  
  * Parameter: `SESS3963c2b234b2db5bb7c5f8b1f641a1a2`
  
  
  * Evidence: `Set-Cookie: SESS3963c2b234b2db5bb7c5f8b1f641a1a2`
  
  
  
  
Instances: 2
  
### Solution
<p>Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such sensitive information.</p>
  
### Reference
* https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html

  
#### CWE Id : 614
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Incomplete or No Cache-control Header Set
##### Low (Medium)
  
  
  
  
#### Description
<p>The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content.</p>
  
  
  
* URL: [https://service-public.nc/CHANGELOG.txt](https://service-public.nc/CHANGELOG.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://service-public.nc/LICENSE.txt](https://service-public.nc/LICENSE.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://service-public.nc/MAINTAINERS.txt](https://service-public.nc/MAINTAINERS.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://service-public.nc/INSTALL.mysql.txt](https://service-public.nc/INSTALL.mysql.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://service-public.nc/robots.txt](https://service-public.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://service-public.nc/install.php](https://service-public.nc/install.php)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `no-cache, must-revalidate`
  
  
  
  
* URL: [https://service-public.nc/INSTALL.txt](https://service-public.nc/INSTALL.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://service-public.nc/sitemap.xml](https://service-public.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `must-revalidate`
  
  
  
  
* URL: [https://service-public.nc/INSTALL.pgsql.txt](https://service-public.nc/INSTALL.pgsql.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://service-public.nc/](https://service-public.nc/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `public, max-age=600`
  
  
  
  
* URL: [https://service-public.nc/INSTALL.sqlite.txt](https://service-public.nc/INSTALL.sqlite.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
Instances: 11
  
### Solution
<p>Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate.</p>
  
### Reference
* https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control

  
#### CWE Id : 525
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Debug Error Messages
##### Low (Medium)
  
  
  
  
#### Description
<p>The response appeared to contain common error messages returned by platforms such as ASP.NET, and Web-servers such as IIS and Apache. You can configure the list of common debug messages.</p>
  
  
  
* URL: [https://service-public.nc/CHANGELOG.txt](https://service-public.nc/CHANGELOG.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `internal server error`
  
  
  
  
Instances: 1
  
### Solution
<p>Disable debugging messages before pushing to production.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Permissions Policy Header Not Set
##### Low (Medium)
  
  
  
  
#### Description
<p>Permissions Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Permissions Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.</p>
  
  
  
* URL: [https://service-public.nc/xmlrpc.php](https://service-public.nc/xmlrpc.php)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/user/logout/](https://service-public.nc/user/logout/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/user/login/](https://service-public.nc/user/login/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/user/password/](https://service-public.nc/user/password/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/install.php](https://service-public.nc/install.php)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/update.php](https://service-public.nc/update.php)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/user/register/](https://service-public.nc/user/register/)
  
  
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
  
  
  
* URL: [https://service-public.nc/misc/*.js$](https://service-public.nc/misc/*.js$)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.css](https://service-public.nc/misc/*.css)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.jpg](https://service-public.nc/misc/*.jpg)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.css$](https://service-public.nc/misc/*.css$)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.png](https://service-public.nc/misc/*.png)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.jpeg](https://service-public.nc/misc/*.jpeg)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.gif](https://service-public.nc/misc/*.gif)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/sitemap.xml](https://service-public.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.js](https://service-public.nc/misc/*.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/robots.txt](https://service-public.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/](https://service-public.nc/)
  
  
  * Method: `GET`
  
  
  
  
Instances: 11
  
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
  
  
  
* URL: [https://service-public.nc/INSTALL.pgsql.txt](https://service-public.nc/INSTALL.pgsql.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://service-public.nc/CHANGELOG.txt](https://service-public.nc/CHANGELOG.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://service-public.nc/LICENSE.txt](https://service-public.nc/LICENSE.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://service-public.nc/INSTALL.mysql.txt](https://service-public.nc/INSTALL.mysql.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://service-public.nc/particuliers](https://service-public.nc/particuliers)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://service-public.nc/MAINTAINERS.txt](https://service-public.nc/MAINTAINERS.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://service-public.nc/](https://service-public.nc/)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://service-public.nc/robots.txt](https://service-public.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://service-public.nc/INSTALL.sqlite.txt](https://service-public.nc/INSTALL.sqlite.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://service-public.nc/INSTALL.txt](https://service-public.nc/INSTALL.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://service-public.nc/UPGRADE.txt](https://service-public.nc/UPGRADE.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
Instances: 11
  
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
  
  
  
* URL: [https://service-public.nc/modules/*.js$](https://service-public.nc/modules/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `nc/sites/default/files/css/css_lQaZfjVpwP_oGNqdtWCSpJT1EMqXdMiU84ekLLxQnc4`
  
  
  
  
* URL: [https://service-public.nc/misc/*.css$](https://service-public.nc/misc/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `nc/sites/default/files/css/css_lQaZfjVpwP_oGNqdtWCSpJT1EMqXdMiU84ekLLxQnc4`
  
  
  
  
* URL: [https://service-public.nc/misc/*.js$](https://service-public.nc/misc/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `nc/sites/default/files/css/css_lQaZfjVpwP_oGNqdtWCSpJT1EMqXdMiU84ekLLxQnc4`
  
  
  
  
* URL: [https://service-public.nc/modules/*.css$](https://service-public.nc/modules/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `nc/sites/default/files/css/css_lQaZfjVpwP_oGNqdtWCSpJT1EMqXdMiU84ekLLxQnc4`
  
  
  
  
* URL: [https://service-public.nc/misc/](https://service-public.nc/misc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `nc/sites/default/files/css/css_lQaZfjVpwP_oGNqdtWCSpJT1EMqXdMiU84ekLLxQnc4`
  
  
  
  
* URL: [https://service-public.nc/profiles/*.js$](https://service-public.nc/profiles/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `nc/sites/default/files/css/css_lQaZfjVpwP_oGNqdtWCSpJT1EMqXdMiU84ekLLxQnc4`
  
  
  
  
* URL: [https://service-public.nc/profiles/*.css$](https://service-public.nc/profiles/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `nc/sites/default/files/css/css_lQaZfjVpwP_oGNqdtWCSpJT1EMqXdMiU84ekLLxQnc4`
  
  
  
  
* URL: [https://service-public.nc/includes/](https://service-public.nc/includes/)
  
  
  * Method: `GET`
  
  
  * Evidence: `nc/sites/default/files/css/css_lQaZfjVpwP_oGNqdtWCSpJT1EMqXdMiU84ekLLxQnc4`
  
  
  
  
* URL: [https://service-public.nc/themes/*.css$](https://service-public.nc/themes/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `nc/sites/default/files/css/css_lQaZfjVpwP_oGNqdtWCSpJT1EMqXdMiU84ekLLxQnc4`
  
  
  
  
* URL: [https://service-public.nc/themes/*.js$](https://service-public.nc/themes/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `nc/sites/default/files/css/css_lQaZfjVpwP_oGNqdtWCSpJT1EMqXdMiU84ekLLxQnc4`
  
  
  
  
* URL: [https://service-public.nc/](https://service-public.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `nc/sites/default/files/css/css_lQaZfjVpwP_oGNqdtWCSpJT1EMqXdMiU84ekLLxQnc4`
  
  
  
  
Instances: 11
  
### Solution
<p>Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.</p>
  
### Other information
<p>���׬�ןj�m���z�ܲ�ܲ��A�_�Zp?�\x00066�mX$�%=D2��2%<��\x000b/\x0014's</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Low)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [https://service-public.nc/misc/*.css$](https://service-public.nc/misc/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [https://service-public.nc/modules/*.css$](https://service-public.nc/modules/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://service-public.nc/misc/*.css$](https://service-public.nc/misc/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://service-public.nc/](https://service-public.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://service-public.nc/](https://service-public.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [https://service-public.nc/misc/*.js$](https://service-public.nc/misc/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://service-public.nc/modules/*.css$](https://service-public.nc/modules/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [https://service-public.nc/modules/*.css$](https://service-public.nc/modules/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [https://service-public.nc/misc/*.js$](https://service-public.nc/misc/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [https://service-public.nc/misc/*.js$](https://service-public.nc/misc/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [https://service-public.nc/misc/*.css$](https://service-public.nc/misc/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
Instances: 11
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bQUERY\b and was detected in the element starting with: "<script type="application/ld+json"></p><p>        {</p><p>          "@context": "http://schema.org",</p><p>          "@type": "WebSite",</p><p>         ", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Modern Web Application
##### Informational (Medium)
  
  
  
  
#### Description
<p>The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.</p>
  
  
  
* URL: [https://service-public.nc/themes/*.js$](https://service-public.nc/themes/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content"></a>`
  
  
  
  
* URL: [https://service-public.nc/themes/*.css$](https://service-public.nc/themes/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content"></a>`
  
  
  
  
* URL: [https://service-public.nc/includes/](https://service-public.nc/includes/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content"></a>`
  
  
  
  
* URL: [https://service-public.nc/](https://service-public.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content"></a>`
  
  
  
  
* URL: [https://service-public.nc/modules/*.css$](https://service-public.nc/modules/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content"></a>`
  
  
  
  
* URL: [https://service-public.nc/misc/](https://service-public.nc/misc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content"></a>`
  
  
  
  
* URL: [https://service-public.nc/misc/*.css$](https://service-public.nc/misc/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content"></a>`
  
  
  
  
* URL: [https://service-public.nc/modules/*.js$](https://service-public.nc/modules/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content"></a>`
  
  
  
  
* URL: [https://service-public.nc/profiles/*.css$](https://service-public.nc/profiles/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content"></a>`
  
  
  
  
* URL: [https://service-public.nc/misc/*.js$](https://service-public.nc/misc/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content"></a>`
  
  
  
  
* URL: [https://service-public.nc/profiles/*.js$](https://service-public.nc/profiles/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content"></a>`
  
  
  
  
Instances: 11
  
### Solution
<p>This is an informational alert and so no changes are required.</p>
  
### Other information
<p>Links have been found that do not have traditional href attributes, which is an indication that this is a modern web application.</p>
  
### Reference
* 

  
#### Source ID : 3

  
  
  
  
### Storable and Cacheable Content
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users.  If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.</p>
  
  
  
* URL: [https://service-public.nc/robots.txt](https://service-public.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://service-public.nc/misc/*.js$](https://service-public.nc/misc/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `max-age=600`
  
  
  
  
* URL: [https://service-public.nc/](https://service-public.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `max-age=600`
  
  
  
  
* URL: [https://service-public.nc/sitemap.xml](https://service-public.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `Wed, 01 Sep 2021 00:29:17 +0000`
  
  
  
  
* URL: [https://service-public.nc/misc/*.css$](https://service-public.nc/misc/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `max-age=600`
  
  
  
  
Instances: 5
  
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

  
  
  
  
### Storable but Non-Cacheable Content
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar requests from other users. </p>
  
  
  
* URL: [https://service-public.nc/misc/*.css](https://service-public.nc/misc/*.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `no-cache`
  
  
  
  
* URL: [https://service-public.nc/misc/*.jpg](https://service-public.nc/misc/*.jpg)
  
  
  * Method: `GET`
  
  
  * Evidence: `no-cache`
  
  
  
  
* URL: [https://service-public.nc/misc/*.jpeg](https://service-public.nc/misc/*.jpeg)
  
  
  * Method: `GET`
  
  
  * Evidence: `no-cache`
  
  
  
  
* URL: [https://service-public.nc/misc/*.gif](https://service-public.nc/misc/*.gif)
  
  
  * Method: `GET`
  
  
  * Evidence: `no-cache`
  
  
  
  
* URL: [https://service-public.nc/misc/*.png](https://service-public.nc/misc/*.png)
  
  
  * Method: `GET`
  
  
  * Evidence: `no-cache`
  
  
  
  
* URL: [https://service-public.nc/misc/*.js](https://service-public.nc/misc/*.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `no-cache`
  
  
  
  
Instances: 6
  
### Solution
<p></p>
  
### Reference
* https://tools.ietf.org/html/rfc7234
* https://tools.ietf.org/html/rfc7231
* http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234)

  
#### CWE Id : 524
  
#### WASC Id : 13
  
#### Source ID : 3
