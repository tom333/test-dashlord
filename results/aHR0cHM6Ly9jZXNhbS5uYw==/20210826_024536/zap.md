
# ZAP Scanning Report

Generated on Thu, 26 Aug 2021 02:29:43


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 3 |
| Low | 9 |
| Informational | 8 |

## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- | 
| Content Security Policy (CSP) Header Not Set | Medium | 11 | 
| Reverse Tabnabbing | Medium | 11 | 
| Sub Resource Integrity Attribute Missing | Medium | 10 | 
| Absence of Anti-CSRF Tokens | Low | 10 | 
| Big Redirect Detected (Potential Sensitive Information Leak) | Low | 2 | 
| Cookie without SameSite Attribute | Low | 12 | 
| Cross-Domain JavaScript Source File Inclusion | Low | 9 | 
| Dangerous JS Functions | Low | 1 | 
| Incomplete or No Cache-control Header Set | Low | 11 | 
| Permissions Policy Header Not Set | Low | 11 | 
| Strict-Transport-Security Header Not Set | Low | 11 | 
| X-Content-Type-Options Header Missing | Low | 12 | 
| Base64 Disclosure | Informational | 11 | 
| Information Disclosure - Suspicious Comments | Informational | 10 | 
| Modern Web Application | Informational | 11 | 
| Non-Storable Content | Informational | 10 | 
| Storable and Cacheable Content | Informational | 1 | 
| Timestamp Disclosure - Unix | Informational | 2 | 
| User Controllable HTML Element Attribute (Potential XSS) | Informational | 5 | 

## Alert Detail


  
  
  
  
### Content Security Policy (CSP) Header Not Set
##### Medium (High)
  
  
  
  
#### Description
<p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.</p>
  
  
  
* URL: [https://cesam.nc/core/*.jpeg](https://cesam.nc/core/*.jpeg)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.css](https://cesam.nc/core/*.css)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.js$](https://cesam.nc/core/*.js$)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.js](https://cesam.nc/core/*.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.jpg](https://cesam.nc/core/*.jpg)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.png](https://cesam.nc/core/*.png)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/sitemap.xml](https://cesam.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.css$](https://cesam.nc/core/*.css$)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.gif](https://cesam.nc/core/*.gif)
  
  
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
  
  
  
* URL: [https://cesam.nc/sitemap.xml](https://cesam.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a alt="Facebook" href="https://www.facebook.com/cesamnc" target="_blank" title="Facebook" class="fb"><i class="fa fa-facebook"></i></a>`
  
  
  
  
* URL: [https://cesam.nc/core/*.css$](https://cesam.nc/core/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a alt="Facebook" href="https://www.facebook.com/cesamnc" target="_blank" title="Facebook" class="fb"><i class="fa fa-facebook"></i></a>`
  
  
  
  
* URL: [https://cesam.nc/profiles/](https://cesam.nc/profiles/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a alt="Facebook" href="https://www.facebook.com/cesamnc" target="_blank" title="Facebook" class="fb"><i class="fa fa-facebook"></i></a>`
  
  
  
  
* URL: [https://cesam.nc/core/*.svg](https://cesam.nc/core/*.svg)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a alt="Facebook" href="https://www.facebook.com/cesamnc" target="_blank" title="Facebook" class="fb"><i class="fa fa-facebook"></i></a>`
  
  
  
  
* URL: [https://cesam.nc/profiles/*.js$](https://cesam.nc/profiles/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a alt="Facebook" href="https://www.facebook.com/cesamnc" target="_blank" title="Facebook" class="fb"><i class="fa fa-facebook"></i></a>`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://gouv.nc/info-coronavirus-covid-19/infos-economie" target="_blank">gouv.nc</a>`
  
  
  
  
* URL: [https://cesam.nc/core/](https://cesam.nc/core/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a alt="Facebook" href="https://www.facebook.com/cesamnc" target="_blank" title="Facebook" class="fb"><i class="fa fa-facebook"></i></a>`
  
  
  
  
* URL: [https://cesam.nc/core/*.js$](https://cesam.nc/core/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a alt="Facebook" href="https://www.facebook.com/cesamnc" target="_blank" title="Facebook" class="fb"><i class="fa fa-facebook"></i></a>`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="https://gouv.nc/info-coronavirus-covid-19/infos-economie" target="_blank">gouv.nc</a>`
  
  
  
  
* URL: [https://cesam.nc/profiles/*.css$](https://cesam.nc/profiles/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a alt="Facebook" href="https://www.facebook.com/cesamnc" target="_blank" title="Facebook" class="fb"><i class="fa fa-facebook"></i></a>`
  
  
  
  
* URL: [https://cesam.nc/profiles/*.svg](https://cesam.nc/profiles/*.svg)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a alt="Facebook" href="https://www.facebook.com/cesamnc" target="_blank" title="Facebook" class="fb"><i class="fa fa-facebook"></i></a>`
  
  
  
  
Instances: 11
  
### Solution
<p>Do not use a target attribute, or if you have to then also add the attribute: rel="noopener noreferrer".</p>
  
### Reference
* https://owasp.org/www-community/attacks/Reverse_Tabnabbing
* https://dev.to/ben/the-targetblank-vulnerability-by-example
* https://mathiasbynens.github.io/rel-noopener/
* https://medium.com/@jitbit/target-blank-the-most-underestimated-vulnerability-ever-96e328301f4c

  
#### Source ID : 3

  
  
  
  
### Sub Resource Integrity Attribute Missing
##### Medium (High)
  
  
  
  
#### Description
<p>The integrity attribute is missing on a script or link tag served by an external server. The integrity tag prevents an attacker who have gained access to this server from injecting a malicious content. </p>
  
  
  
* URL: [https://cesam.nc/core/*.css$](https://cesam.nc/core/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5"></script>`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5"></script>`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script src="https://www.google.com/recaptcha/api.js?hl=fr"></script>`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script src="https://www.google.com/recaptcha/api.js?hl=fr"></script>`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5"></script>`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script src="https://sibforms.com/forms/end-form/build/main.js"></script>`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script src="https://sibforms.com/forms/end-form/build/main.js"></script>`
  
  
  
  
* URL: [https://cesam.nc/sitemap.xml](https://cesam.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5"></script>`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="stylesheet" href="https://sibforms.com/forms/end-form/build/sib-styles.css">`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<link rel="stylesheet" href="https://sibforms.com/forms/end-form/build/sib-styles.css">`
  
  
  
  
Instances: 10
  
### Solution
<p>Provide a valid integrity attribute to the tag.</p>
  
### Reference
* https://developer.mozilla.org/en/docs/Web/Security/Subresource_Integrity

  
#### CWE Id : 345
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Absence of Anti-CSRF Tokens
##### Low (Medium)
  
  
  
  
#### Description
<p>No Anti-CSRF tokens were found in a HTML submission form.</p><p>A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.</p><p></p><p>CSRF attacks are effective in a number of situations, including:</p><p>    * The victim has an active session on the target site.</p><p>    * The victim is authenticated via HTTP auth on the target site.</p><p>    * The victim is on the same local network as the target site.</p><p></p><p>CSRF has primarily been used to perform an action against a target site using the victim's privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.</p>
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form class="views-exposed-form" method="get" data-drupal-selector="views-exposed-form-dispositif-default" action="/dispositif" id="views-exposed-form-dispositif-default" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://cesam.nc/dispositif/1](https://cesam.nc/dispositif/1)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form class="views-exposed-form" method="get" data-drupal-selector="views-exposed-form-dispositif-dispositif-view" action="/dispositif/1" id="views-exposed-form-dispositif-dispositif-view" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://cesam.nc/node/20](https://cesam.nc/node/20)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form class="views-exposed-form" method="get" data-drupal-selector="views-exposed-form-dispositif-default" action="/dispositif" id="views-exposed-form-dispositif-default" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://cesam.nc/node/20](https://cesam.nc/node/20)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form id="sib-form" method="POST" action="https://981c5932.sibforms.com/serve/MUIEAC58k3Ko8vSuER3gO1bXxLAmqr9xKBZdACW7Ro-mrsr-GTQqjzT5RLYvCqqZf3iKZrhG3fhyFRdJx5HoXj2sVtQBmdCktH4YOep3P76pu41qIRkgCZvRWrjejY8xugUKyH6jQd3scFmxDaubHy2l0XviB38n3X9kzWgpst9WzcDZsZaDXhKerhqDhwPNPEw8KPy-HaahKL4A"
        data-type="subscription">`
  
  
  
  
* URL: [https://cesam.nc/dispositif?type=demarche](https://cesam.nc/dispositif?type=demarche)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form class="views-exposed-form" method="get" data-drupal-selector="views-exposed-form-dispositif-dispositif-view" action="/dispositif" id="views-exposed-form-dispositif-dispositif-view" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://cesam.nc/dispositif?type=aide_financiere](https://cesam.nc/dispositif?type=aide_financiere)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form class="views-exposed-form" method="get" data-drupal-selector="views-exposed-form-dispositif-dispositif-view" action="/dispositif" id="views-exposed-form-dispositif-dispositif-view" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form id="sib-form" method="POST" action="https://981c5932.sibforms.com/serve/MUIEAC58k3Ko8vSuER3gO1bXxLAmqr9xKBZdACW7Ro-mrsr-GTQqjzT5RLYvCqqZf3iKZrhG3fhyFRdJx5HoXj2sVtQBmdCktH4YOep3P76pu41qIRkgCZvRWrjejY8xugUKyH6jQd3scFmxDaubHy2l0XviB38n3X9kzWgpst9WzcDZsZaDXhKerhqDhwPNPEw8KPy-HaahKL4A"
        data-type="subscription">`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form id="sib-form" method="POST" action="https://981c5932.sibforms.com/serve/MUIEAC58k3Ko8vSuER3gO1bXxLAmqr9xKBZdACW7Ro-mrsr-GTQqjzT5RLYvCqqZf3iKZrhG3fhyFRdJx5HoXj2sVtQBmdCktH4YOep3P76pu41qIRkgCZvRWrjejY8xugUKyH6jQd3scFmxDaubHy2l0XviB38n3X9kzWgpst9WzcDZsZaDXhKerhqDhwPNPEw8KPy-HaahKL4A"
        data-type="subscription">`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form class="views-exposed-form" method="get" data-drupal-selector="views-exposed-form-dispositif-default" action="/dispositif" id="views-exposed-form-dispositif-default" accept-charset="UTF-8">`
  
  
  
  
* URL: [https://cesam.nc/dispositif?type=accompagnement](https://cesam.nc/dispositif?type=accompagnement)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form class="views-exposed-form" method="get" data-drupal-selector="views-exposed-form-dispositif-dispositif-view" action="/dispositif" id="views-exposed-form-dispositif-dispositif-view" accept-charset="UTF-8">`
  
  
  
  
Instances: 10
  
### Solution
<p>Phase: Architecture and Design</p><p>Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.</p><p>For example, use anti-CSRF packages such as the OWASP CSRFGuard.</p><p></p><p>Phase: Implementation</p><p>Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.</p><p></p><p>Phase: Architecture and Design</p><p>Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Use the ESAPI Session Management control.</p><p>This control includes a component for CSRF.</p><p></p><p>Do not use the GET method for any request that triggers a state change.</p><p></p><p>Phase: Implementation</p><p>Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.</p>
  
### Other information
<p>No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF] was found in the following HTML form: [Form 1: "edit-localite-5" "edit-localite-6" "edit-localite-7" "edit-profil-entreprise-10" "edit-profil-entreprise-11" "edit-profil-entreprise-12" "edit-profil-entreprise-40" "edit-profil-entreprise-41" "edit-profil-entreprise-42" "edit-profil-entreprise-43" "edit-profil-entreprise-44" "edit-profil-entreprise-45" "edit-profil-entreprise-46" "edit-profil-entreprise-9" "edit-secteur-activite-13" "edit-secteur-activite-14" "edit-secteur-activite-15" "edit-secteur-activite-16" "edit-secteur-activite-17" "edit-secteur-activite-20" "edit-secteur-activite-21" "edit-secteur-activite-22" "edit-secteur-activite-23" "edit-secteur-activite-24" "edit-secteur-activite-25" "edit-secteur-activite-26" "edit-secteur-activite-27" "edit-secteur-activite-28" "edit-secteur-activite-29" "edit-secteur-activite-30" "edit-secteur-activite-31" "edit-secteur-activite-32" "edit-secteur-activite-33" "edit-secteur-activite-34" "edit-secteur-activite-35" "edit-secteur-activite-36" "edit-secteur-activite-37" "edit-secteur-activite-38" "edit-secteur-activite-39" ].</p>
  
### Reference
* http://projects.webappsec.org/Cross-Site-Request-Forgery
* http://cwe.mitre.org/data/definitions/352.html

  
#### CWE Id : 352
  
#### WASC Id : 9
  
#### Source ID : 3

  
  
  
  
### Big Redirect Detected (Potential Sensitive Information Leak)
##### Low (Medium)
  
  
  
  
#### Description
<p>The server has responded with a redirect that seems to provide a large response. This may indicate that although the server sent a redirect it also responded with body content (which may include sensitive details, PII, etc.).</p>
  
  
  
* URL: [https://cesam.nc/index.php/search/](https://cesam.nc/index.php/search/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/search/](https://cesam.nc/search/)
  
  
  * Method: `GET`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that no sensitive information is leaked via redirect responses. Redirect responses should have almost no content.</p>
  
### Other information
<p>Location header URI length: 38 [https://cesam.nc/index.php/search/node].</p><p>Predicted response size: 338.</p><p>Response Body Length: 398.</p>
  
### Reference
* 

  
#### CWE Id : 201
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Cookie without SameSite Attribute
##### Low (Medium)
  
  
  
  
#### Description
<p>A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.</p>
  
  
  
* URL: [https://cesam.nc/dispositif/1?localite%5B5%5D=5&localite%5B6%5D=6&localite%5B7%5D=7&profil_entreprise%5B10%5D=10&profil_entreprise%5B11%5D=11&profil_entreprise%5B12%5D=12&profil_entreprise%5B40%5D=40&profil_entreprise%5B41%5D=41&profil_entreprise%5B42%5D=42&profil_entreprise%5B43%5D=43&profil_entreprise%5B44%5D=44&profil_entreprise%5B45%5D=45&profil_entreprise%5B46%5D=46&profil_entreprise%5B9%5D=9&secteur_activite%5B13%5D=13&secteur_activite%5B14%5D=14&secteur_activite%5B15%5D=15&secteur_activite%5B16%5D=16&secteur_activite%5B17%5D=17&secteur_activite%5B20%5D=20&secteur_activite%5B21%5D=21&secteur_activite%5B22%5D=22&secteur_activite%5B23%5D=23&secteur_activite%5B24%5D=24&secteur_activite%5B25%5D=25&secteur_activite%5B26%5D=26&secteur_activite%5B27%5D=27&secteur_activite%5B28%5D=28&secteur_activite%5B29%5D=29&secteur_activite%5B30%5D=30&secteur_activite%5B31%5D=31&secteur_activite%5B32%5D=32&secteur_activite%5B33%5D=33&secteur_activite%5B34%5D=34&secteur_activite%5B35%5D=35&secteur_activite%5B36%5D=36&secteur_activite%5B37%5D=37&secteur_activite%5B38%5D=38&secteur_activite%5B39%5D=39&type=All](https://cesam.nc/dispositif/1?localite%5B5%5D=5&localite%5B6%5D=6&localite%5B7%5D=7&profil_entreprise%5B10%5D=10&profil_entreprise%5B11%5D=11&profil_entreprise%5B12%5D=12&profil_entreprise%5B40%5D=40&profil_entreprise%5B41%5D=41&profil_entreprise%5B42%5D=42&profil_entreprise%5B43%5D=43&profil_entreprise%5B44%5D=44&profil_entreprise%5B45%5D=45&profil_entreprise%5B46%5D=46&profil_entreprise%5B9%5D=9&secteur_activite%5B13%5D=13&secteur_activite%5B14%5D=14&secteur_activite%5B15%5D=15&secteur_activite%5B16%5D=16&secteur_activite%5B17%5D=17&secteur_activite%5B20%5D=20&secteur_activite%5B21%5D=21&secteur_activite%5B22%5D=22&secteur_activite%5B23%5D=23&secteur_activite%5B24%5D=24&secteur_activite%5B25%5D=25&secteur_activite%5B26%5D=26&secteur_activite%5B27%5D=27&secteur_activite%5B28%5D=28&secteur_activite%5B29%5D=29&secteur_activite%5B30%5D=30&secteur_activite%5B31%5D=31&secteur_activite%5B32%5D=32&secteur_activite%5B33%5D=33&secteur_activite%5B34%5D=34&secteur_activite%5B35%5D=35&secteur_activite%5B36%5D=36&secteur_activite%5B37%5D=37&secteur_activite%5B38%5D=38&secteur_activite%5B39%5D=39&type=All)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
* URL: [https://cesam.nc/accompagnement-et-conseil/mediation-de-credit-en-cas-de-refus-de-credit](https://cesam.nc/accompagnement-et-conseil/mediation-de-credit-en-cas-de-refus-de-credit)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
* URL: [https://cesam.nc/formalite-en-ligne/demander-une-admission-au-benefice-du-chomage-partiel-en-ligne](https://cesam.nc/formalite-en-ligne/demander-une-admission-au-benefice-du-chomage-partiel-en-ligne)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
* URL: [https://cesam.nc/aide-financiere/report-du-paiement-de-lirpp-pour-les-travailleurs-independants](https://cesam.nc/aide-financiere/report-du-paiement-de-lirpp-pour-les-travailleurs-independants)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
* URL: [https://cesam.nc/formalite-en-ligne/demande-dautorisation-de-tournages-relative-aux-especes-et-aires-protegees-en](https://cesam.nc/formalite-en-ligne/demande-dautorisation-de-tournages-relative-aux-especes-et-aires-protegees-en)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
* URL: [https://cesam.nc/aide-financiere/aide-la-tresorerie-des-entreprises](https://cesam.nc/aide-financiere/aide-la-tresorerie-des-entreprises)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
* URL: [https://cesam.nc/aide-financiere/report-des-charges-fiscales](https://cesam.nc/aide-financiere/report-des-charges-fiscales)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
* URL: [https://cesam.nc/index.php/search/node](https://cesam.nc/index.php/search/node)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
* URL: [https://cesam.nc/dispositif?localite%5B5%5D=5&localite%5B6%5D=6&localite%5B7%5D=7&profil_entreprise%5B10%5D=10&profil_entreprise%5B11%5D=11&profil_entreprise%5B12%5D=12&profil_entreprise%5B40%5D=40&profil_entreprise%5B41%5D=41&profil_entreprise%5B42%5D=42&profil_entreprise%5B43%5D=43&profil_entreprise%5B44%5D=44&profil_entreprise%5B45%5D=45&profil_entreprise%5B46%5D=46&profil_entreprise%5B9%5D=9&secteur_activite%5B13%5D=13&secteur_activite%5B14%5D=14&secteur_activite%5B15%5D=15&secteur_activite%5B16%5D=16&secteur_activite%5B17%5D=17&secteur_activite%5B20%5D=20&secteur_activite%5B21%5D=21&secteur_activite%5B22%5D=22&secteur_activite%5B23%5D=23&secteur_activite%5B24%5D=24&secteur_activite%5B25%5D=25&secteur_activite%5B26%5D=26&secteur_activite%5B27%5D=27&secteur_activite%5B28%5D=28&secteur_activite%5B29%5D=29&secteur_activite%5B30%5D=30&secteur_activite%5B31%5D=31&secteur_activite%5B32%5D=32&secteur_activite%5B33%5D=33&secteur_activite%5B34%5D=34&secteur_activite%5B35%5D=35&secteur_activite%5B36%5D=36&secteur_activite%5B37%5D=37&secteur_activite%5B38%5D=38&secteur_activite%5B39%5D=39&type=All](https://cesam.nc/dispositif?localite%5B5%5D=5&localite%5B6%5D=6&localite%5B7%5D=7&profil_entreprise%5B10%5D=10&profil_entreprise%5B11%5D=11&profil_entreprise%5B12%5D=12&profil_entreprise%5B40%5D=40&profil_entreprise%5B41%5D=41&profil_entreprise%5B42%5D=42&profil_entreprise%5B43%5D=43&profil_entreprise%5B44%5D=44&profil_entreprise%5B45%5D=45&profil_entreprise%5B46%5D=46&profil_entreprise%5B9%5D=9&secteur_activite%5B13%5D=13&secteur_activite%5B14%5D=14&secteur_activite%5B15%5D=15&secteur_activite%5B16%5D=16&secteur_activite%5B17%5D=17&secteur_activite%5B20%5D=20&secteur_activite%5B21%5D=21&secteur_activite%5B22%5D=22&secteur_activite%5B23%5D=23&secteur_activite%5B24%5D=24&secteur_activite%5B25%5D=25&secteur_activite%5B26%5D=26&secteur_activite%5B27%5D=27&secteur_activite%5B28%5D=28&secteur_activite%5B29%5D=29&secteur_activite%5B30%5D=30&secteur_activite%5B31%5D=31&secteur_activite%5B32%5D=32&secteur_activite%5B33%5D=33&secteur_activite%5B34%5D=34&secteur_activite%5B35%5D=35&secteur_activite%5B36%5D=36&secteur_activite%5B37%5D=37&secteur_activite%5B38%5D=38&secteur_activite%5B39%5D=39&type=All)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
* URL: [https://cesam.nc/aide-financiere/fonds-de-solidarite-aux-entreprises](https://cesam.nc/aide-financiere/fonds-de-solidarite-aux-entreprises)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
* URL: [https://cesam.nc/accompagnement-et-conseil/sinformer-des-mesures-prises-dans-le-cadre-de-la-crise-covid](https://cesam.nc/accompagnement-et-conseil/sinformer-des-mesures-prises-dans-le-cadre-de-la-crise-covid)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
* URL: [https://cesam.nc/aide-financiere/pret-garantie-par-letat-soutien-conjoncturel](https://cesam.nc/aide-financiere/pret-garantie-par-letat-soutien-conjoncturel)
  
  
  * Method: `GET`
  
  
  * Parameter: `SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  * Evidence: `Set-Cookie: SSESSa8025fa4ac436431082fccd3afcf1a1e`
  
  
  
  
Instances: 12
  
### Solution
<p>Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.</p>
  
### Reference
* https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site

  
#### CWE Id : 1275
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Cross-Domain JavaScript Source File Inclusion
##### Low (Medium)
  
  
  
  
#### Description
<p>The page includes one or more script files from a third-party domain.</p>
  
  
  
* URL: [https://cesam.nc/sitemap.xml](https://cesam.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5"></script>`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5"></script>`
  
  
  
  
* URL: [https://cesam.nc/core/*.css$](https://cesam.nc/core/*.css$)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5"></script>`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://www.google.com/recaptcha/api.js?hl=fr`
  
  
  * Evidence: `<script src="https://www.google.com/recaptcha/api.js?hl=fr"></script>`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://sibforms.com/forms/end-form/build/main.js`
  
  
  * Evidence: `<script src="https://sibforms.com/forms/end-form/build/main.js"></script>`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://www.google.com/recaptcha/api.js?hl=fr`
  
  
  * Evidence: `<script src="https://www.google.com/recaptcha/api.js?hl=fr"></script>`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5"></script>`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://sibforms.com/forms/end-form/build/main.js`
  
  
  * Evidence: `<script src="https://sibforms.com/forms/end-form/build/main.js"></script>`
  
  
  
  
* URL: [https://cesam.nc/core/*.js$](https://cesam.nc/core/*.js$)
  
  
  * Method: `GET`
  
  
  * Parameter: `https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5`
  
  
  * Evidence: `<script async src="https://www.googletagmanager.com/gtag/js?id=G-1X2XK0SSR5"></script>`
  
  
  
  
Instances: 9
  
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
  
  
  
* URL: [https://cesam.nc/core/assets/vendor/jquery/jquery.min.js?v=3.5.1](https://cesam.nc/core/assets/vendor/jquery/jquery.min.js?v=3.5.1)
  
  
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
  
  
  
* URL: [https://cesam.nc/node/164](https://cesam.nc/node/164)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `must-revalidate, no-cache, private`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `must-revalidate, no-cache, private`
  
  
  
  
* URL: [https://cesam.nc/dispositif/1](https://cesam.nc/dispositif/1)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `must-revalidate, no-cache, private`
  
  
  
  
* URL: [https://cesam.nc/robots.txt](https://cesam.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://cesam.nc/README.txt](https://cesam.nc/README.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://cesam.nc/dispositif?type=demarche](https://cesam.nc/dispositif?type=demarche)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `must-revalidate, no-cache, private`
  
  
  
  
* URL: [https://cesam.nc/node/165](https://cesam.nc/node/165)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `must-revalidate, no-cache, private`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `must-revalidate, no-cache, private`
  
  
  
  
* URL: [https://cesam.nc/index.php/filter/tips](https://cesam.nc/index.php/filter/tips)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `must-revalidate, no-cache, private`
  
  
  
  
* URL: [https://cesam.nc/filter/tips](https://cesam.nc/filter/tips)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `must-revalidate, no-cache, private`
  
  
  
  
* URL: [https://cesam.nc/dispositif?type=aide_financiere](https://cesam.nc/dispositif?type=aide_financiere)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `must-revalidate, no-cache, private`
  
  
  
  
Instances: 11
  
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
  
  
  
* URL: [https://cesam.nc/sitemap.xml](https://cesam.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.gif](https://cesam.nc/core/*.gif)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.css$](https://cesam.nc/core/*.css$)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.png](https://cesam.nc/core/*.png)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.jpg](https://cesam.nc/core/*.jpg)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.js](https://cesam.nc/core/*.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.jpeg](https://cesam.nc/core/*.jpeg)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.js$](https://cesam.nc/core/*.js$)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.css](https://cesam.nc/core/*.css)
  
  
  * Method: `GET`
  
  
  
  
Instances: 11
  
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
  
  
  
* URL: [https://cesam.nc/robots.txt](https://cesam.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.css$](https://cesam.nc/core/*.css$)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/sitemap.xml](https://cesam.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.gif](https://cesam.nc/core/*.gif)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.js](https://cesam.nc/core/*.js)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.jpeg](https://cesam.nc/core/*.jpeg)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.css](https://cesam.nc/core/*.css)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.jpg](https://cesam.nc/core/*.jpg)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://cesam.nc/core/*.js$](https://cesam.nc/core/*.js$)
  
  
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
  
  
  
* URL: [https://cesam.nc/core/assets/vendor/jquery-once/jquery.once.min.js?v=2.2.3](https://cesam.nc/core/assets/vendor/jquery-once/jquery.once.min.js?v=2.2.3)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://cesam.nc/core/assets/vendor/jquery/jquery.min.js?v=3.5.1](https://cesam.nc/core/assets/vendor/jquery/jquery.min.js?v=3.5.1)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://cesam.nc/modules/contrib/google_analytics/js/google_analytics_ecc.js](https://cesam.nc/modules/contrib/google_analytics/js/google_analytics_ecc.js)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://cesam.nc/robots.txt](https://cesam.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://cesam.nc/sites/default/files/css/css_aNKhz3-rCorOBXpSJGKUOAMfekCJHZDWz4AQzZAW3iM.css](https://cesam.nc/sites/default/files/css/css_aNKhz3-rCorOBXpSJGKUOAMfekCJHZDWz4AQzZAW3iM.css)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://cesam.nc/themes/custom/cesam/images/logo_cesam.svg](https://cesam.nc/themes/custom/cesam/images/logo_cesam.svg)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://cesam.nc/sites/default/files/css/css_Y4H_4BqmgyCtG7E7YdseTs2qvy9C34c51kBamDdgark.css](https://cesam.nc/sites/default/files/css/css_Y4H_4BqmgyCtG7E7YdseTs2qvy9C34c51kBamDdgark.css)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://cesam.nc/README.txt](https://cesam.nc/README.txt)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://cesam.nc/sites/default/files/css/css_yzJ35ia9tlYsg9_kEyW9TtVozwdBnP8auChonXhkyi8.css](https://cesam.nc/sites/default/files/css/css_yzJ35ia9tlYsg9_kEyW9TtVozwdBnP8auChonXhkyi8.css)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://cesam.nc/core/misc/polyfills/object.assign.js?v=8.9.17](https://cesam.nc/core/misc/polyfills/object.assign.js?v=8.9.17)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://cesam.nc/core/assets/vendor/html5shiv/html5shiv.min.js?v=3.7.3](https://cesam.nc/core/assets/vendor/html5shiv/html5shiv.min.js?v=3.7.3)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://cesam.nc/themes/custom/cesam/images/favicon-32x32.png](https://cesam.nc/themes/custom/cesam/images/favicon-32x32.png)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
Instances: 12
  
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
  
  
  
* URL: [https://cesam.nc/core/*.css$](https://cesam.nc/core/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sites/default/files/css/css_87GMcmxT1ib8ziQiU2KUAnTDFtZQV6iP-KGslA9LigM`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sites/default/files/css/css_aNKhz3-rCorOBXpSJGKUOAMfekCJHZDWz4AQzZAW3iM`
  
  
  
  
* URL: [https://cesam.nc/core/](https://cesam.nc/core/)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sites/default/files/css/css_87GMcmxT1ib8ziQiU2KUAnTDFtZQV6iP-KGslA9LigM`
  
  
  
  
* URL: [https://cesam.nc/core/*.svg](https://cesam.nc/core/*.svg)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sites/default/files/css/css_87GMcmxT1ib8ziQiU2KUAnTDFtZQV6iP-KGslA9LigM`
  
  
  
  
* URL: [https://cesam.nc/profiles/](https://cesam.nc/profiles/)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sites/default/files/css/css_87GMcmxT1ib8ziQiU2KUAnTDFtZQV6iP-KGslA9LigM`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sites/default/files/css/css_aNKhz3-rCorOBXpSJGKUOAMfekCJHZDWz4AQzZAW3iM`
  
  
  
  
* URL: [https://cesam.nc/sitemap.xml](https://cesam.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sites/default/files/css/css_87GMcmxT1ib8ziQiU2KUAnTDFtZQV6iP-KGslA9LigM`
  
  
  
  
* URL: [https://cesam.nc/profiles/*.js$](https://cesam.nc/profiles/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sites/default/files/css/css_87GMcmxT1ib8ziQiU2KUAnTDFtZQV6iP-KGslA9LigM`
  
  
  
  
* URL: [https://cesam.nc/core/*.js$](https://cesam.nc/core/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sites/default/files/css/css_87GMcmxT1ib8ziQiU2KUAnTDFtZQV6iP-KGslA9LigM`
  
  
  
  
* URL: [https://cesam.nc/profiles/*.svg](https://cesam.nc/profiles/*.svg)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sites/default/files/css/css_87GMcmxT1ib8ziQiU2KUAnTDFtZQV6iP-KGslA9LigM`
  
  
  
  
* URL: [https://cesam.nc/profiles/*.css$](https://cesam.nc/profiles/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sites/default/files/css/css_87GMcmxT1ib8ziQiU2KUAnTDFtZQV6iP-KGslA9LigM`
  
  
  
  
Instances: 11
  
### Solution
<p>Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.</p>
  
### Other information
<p>�ȭz��y����ߊW���,��,���1ɱOX��8��M�P	�\x000c[YA^�?↲P=.(\x000c</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `where`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `where`
  
  
  
  
Instances: 2
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bWHERE\b and was detected 2 times, the first in the element starting with: "<!-- START - We recommend to place the below code where you want the form in your website html  -->", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Low)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [https://cesam.nc/core/*.js$](https://cesam.nc/core/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://cesam.nc/core/*.js$](https://cesam.nc/core/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [https://cesam.nc/sitemap.xml](https://cesam.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [https://cesam.nc/core/*.css$](https://cesam.nc/core/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://cesam.nc/sitemap.xml](https://cesam.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://cesam.nc/core/*.css$](https://cesam.nc/core/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
Instances: 8
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bUSER\b and was detected in the element starting with: "<script type="application/json" data-drupal-selector="drupal-settings-json">{"path":{"baseUrl":"\/","scriptPath":null,"pathPrefi", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Modern Web Application
##### Informational (Medium)
  
  
  
  
#### Description
<p>The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.</p>
  
  
  
* URL: [https://cesam.nc/core/*.js$](https://cesam.nc/core/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content" tabindex="-1"></a>`
  
  
  
  
* URL: [https://cesam.nc/profiles/*.css$](https://cesam.nc/profiles/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content" tabindex="-1"></a>`
  
  
  
  
* URL: [https://cesam.nc/profiles/*.js$](https://cesam.nc/profiles/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content" tabindex="-1"></a>`
  
  
  
  
* URL: [https://cesam.nc/core/](https://cesam.nc/core/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content" tabindex="-1"></a>`
  
  
  
  
* URL: [https://cesam.nc/profiles/](https://cesam.nc/profiles/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content" tabindex="-1"></a>`
  
  
  
  
* URL: [https://cesam.nc/core/*.svg](https://cesam.nc/core/*.svg)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content" tabindex="-1"></a>`
  
  
  
  
* URL: [https://cesam.nc/core/*.css$](https://cesam.nc/core/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content" tabindex="-1"></a>`
  
  
  
  
* URL: [https://cesam.nc/sitemap.xml](https://cesam.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content" tabindex="-1"></a>`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content" tabindex="-1"></a>`
  
  
  
  
* URL: [https://cesam.nc/profiles/*.svg](https://cesam.nc/profiles/*.svg)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content" tabindex="-1"></a>`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id="main-content" tabindex="-1"></a>`
  
  
  
  
Instances: 11
  
### Solution
<p>This is an informational alert and so no changes are required.</p>
  
### Other information
<p>Links have been found that do not have traditional href attributes, which is an indication that this is a modern web application.</p>
  
### Reference
* 

  
#### Source ID : 3

  
  
  
  
### Non-Storable Content
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.</p>
  
  
  
* URL: [https://cesam.nc/core/*.gif](https://cesam.nc/core/*.gif)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://cesam.nc](https://cesam.nc)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://cesam.nc/sitemap.xml](https://cesam.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://cesam.nc/core/*.css$](https://cesam.nc/core/*.css$)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://cesam.nc/core/*.jpg](https://cesam.nc/core/*.jpg)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://cesam.nc/core/*.js](https://cesam.nc/core/*.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://cesam.nc/](https://cesam.nc/)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://cesam.nc/core/*.jpeg](https://cesam.nc/core/*.jpeg)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://cesam.nc/core/*.css](https://cesam.nc/core/*.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
* URL: [https://cesam.nc/core/*.js$](https://cesam.nc/core/*.js$)
  
  
  * Method: `GET`
  
  
  * Evidence: `private`
  
  
  
  
Instances: 10
  
### Solution
<p>The content may be marked as storable by ensuring that the following conditions are satisfied:</p><p>The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)</p><p>The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)</p><p>The "no-store" cache directive must not appear in the request or response header fields</p><p>For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response</p><p>For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)</p><p>In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:</p><p>It must contain an "Expires" header field</p><p>It must contain a "max-age" response directive</p><p>For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive</p><p>It must contain a "Cache Control Extension" that allows it to be cached</p><p>It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).   </p>
  
### Reference
* https://tools.ietf.org/html/rfc7234
* https://tools.ietf.org/html/rfc7231
* http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234)

  
#### CWE Id : 524
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Storable and Cacheable Content
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users.  If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.</p>
  
  
  
* URL: [https://cesam.nc/robots.txt](https://cesam.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
Instances: 1
  
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
  
  
  
* URL: [https://cesam.nc/aide-financiere/report-des-charges-fiscales](https://cesam.nc/aide-financiere/report-des-charges-fiscales)
  
  
  * Method: `GET`
  
  
  * Evidence: `439782037`
  
  
  
  
* URL: [https://cesam.nc/themes/custom/cesam/images/404.svg](https://cesam.nc/themes/custom/cesam/images/404.svg)
  
  
  * Method: `GET`
  
  
  * Evidence: `20010904`
  
  
  
  
Instances: 2
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>439782037, which evaluates to: 1983-12-09 01:40:37</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### User Controllable HTML Element Attribute (Potential XSS)
##### Informational (Low)
  
  
  
  
#### Description
<p>This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.</p>
  
  
  
* URL: [https://cesam.nc/dispositif?type=aide_financiere](https://cesam.nc/dispositif?type=aide_financiere)
  
  
  * Method: `GET`
  
  
  * Parameter: `type`
  
  
  
  
* URL: [https://cesam.nc/dispositif?type=demarche](https://cesam.nc/dispositif?type=demarche)
  
  
  * Method: `GET`
  
  
  * Parameter: `type`
  
  
  
  
* URL: [https://cesam.nc/dispositif?type=accompagnement](https://cesam.nc/dispositif?type=accompagnement)
  
  
  * Method: `GET`
  
  
  * Parameter: `type`
  
  
  
  
* URL: [https://cesam.nc/dispositif?type=accompagnement](https://cesam.nc/dispositif?type=accompagnement)
  
  
  * Method: `GET`
  
  
  * Parameter: `type`
  
  
  
  
* URL: [https://cesam.nc/dispositif?type=accompagnement](https://cesam.nc/dispositif?type=accompagnement)
  
  
  * Method: `GET`
  
  
  * Parameter: `type`
  
  
  
  
Instances: 5
  
### Solution
<p>Validate all input and sanitize output it before writing to any HTML attributes.</p>
  
### Other information
<p>User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:</p><p></p><p>https://cesam.nc/dispositif?type=aide_financiere</p><p></p><p>appears to include user input in: </p><p></p><p>a(n) [option] tag [value] attribute </p><p></p><p>The user input found was:</p><p>type=aide_financiere</p><p></p><p>The user-controlled value was:</p><p>aide_financiere</p>
  
### Reference
* http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-html-attribute

  
#### CWE Id : 20
  
#### WASC Id : 20
  
#### Source ID : 3
