
# ZAP Scanning Report

Generated on Thu, 26 Aug 2021 02:57:50


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 8 |
| Low | 10 |
| Informational | 7 |

## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- | 
| Content Security Policy (CSP) Header Not Set | Medium | 11 | 
| Referer Exposes Session ID | Medium | 2 | 
| Reverse Tabnabbing | Medium | 3 | 
| Session ID in URL Rewrite | Medium | 2 | 
| Source Code Disclosure - Perl | Medium | 2 | 
| Source Code Disclosure - PHP | Medium | 1 | 
| Vulnerable JS Library | Medium | 2 | 
| X-Frame-Options Header Not Set | Medium | 11 | 
| Absence of Anti-CSRF Tokens | Low | 2 | 
| Cookie No HttpOnly Flag | Low | 2 | 
| Cookie without SameSite Attribute | Low | 8 | 
| Cookie Without Secure Flag | Low | 8 | 
| Dangerous JS Functions | Low | 2 | 
| Incomplete or No Cache-control Header Set | Low | 11 | 
| In Page Banner Information Leak | Low | 2 | 
| Permissions Policy Header Not Set | Low | 11 | 
| Strict-Transport-Security Header Not Set | Low | 11 | 
| X-Content-Type-Options Header Missing | Low | 11 | 
| Base64 Disclosure | Informational | 11 | 
| Information Disclosure - Suspicious Comments | Informational | 18 | 
| Modern Web Application | Informational | 11 | 
| Non-Storable Content | Informational | 3 | 
| Storable and Cacheable Content | Informational | 6 | 
| Timestamp Disclosure - Unix | Informational | 12 | 
| User Controllable HTML Element Attribute (Potential XSS) | Informational | 19 | 

## Alert Detail


  
  
  
  
### Content Security Policy (CSP) Header Not Set
##### Medium (High)
  
  
  
  
#### Description
<p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.</p>
  
  
  
* URL: [https://www.impots.nc/sitemap.xml](https://www.impots.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/](https://www.impots.nc/sel/public/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/robots.txt](https://www.impots.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
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

  
  
  
  
### Referer Exposes Session ID
##### Medium (Medium)
  
  
  
  
#### Description
<p>A hyperlink pointing to another host name was found. As session ID URL rewrite is used, it may be disclosed in referer header to external hosts.</p>
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Evidence: `connect.gouv.nc`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Evidence: `connect.gouv.nc`
  
  
  
  
Instances: 2
  
### Solution
<p>This is a risk if the session ID is sensitive and the hyperlink refers to an external or third party host. For secure content, put session ID in secured session cookie.</p>
  
### Reference
* http://seclists.org/lists/webappsec/2002/Oct-Dec/0111.html

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Reverse Tabnabbing
##### Medium (Medium)
  
  
  
  
#### Description
<p>At least one link on this page is vulnerable to Reverse tabnabbing as it uses a target attribute without using both of the "noopener" and "noreferrer" keywords in the "rel" attribute, which allows the target page to take control of this page.</p>
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="http://www.mozilla.org/fr/firefox/fx/" target="_blank">http://www.mozilla.org/fr/firefox/fx/</a>`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a target="_blank" href="https://connect.gouv.nc">En savoir plus sur NC Connect</a>`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a target="_blank" href="https://connect.gouv.nc">En savoir plus sur NC Connect</a>`
  
  
  
  
Instances: 3
  
### Solution
<p>Do not use a target attribute, or if you have to then also add the attribute: rel="noopener noreferrer".</p>
  
### Reference
* https://owasp.org/www-community/attacks/Reverse_Tabnabbing
* https://dev.to/ben/the-targetblank-vulnerability-by-example
* https://mathiasbynens.github.io/rel-noopener/
* https://medium.com/@jitbit/target-blank-the-most-underestimated-vulnerability-ever-96e328301f4c

  
#### Source ID : 3

  
  
  
  
### Session ID in URL Rewrite
##### Medium (High)
  
  
  
  
#### Description
<p>URL rewrite is used to track user session ID. The session ID may be disclosed via cross-site referer header. In addition, the session ID might be stored in browser history or server logs.</p>
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Evidence: `jsessionid=F968A1BA2E29F26F86447E72EBC90B6C`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Evidence: `jsessionid=5166A7037B10DB0811D069E1B73031B4`
  
  
  
  
Instances: 2
  
### Solution
<p>For secure content, put session ID in a cookie. To be even more secure consider using a combination of cookie and URL rewrite.</p>
  
### Reference
* http://seclists.org/lists/webappsec/2002/Oct-Dec/0111.html

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Source Code Disclosure - Perl
##### Medium (Medium)
  
  
  
  
#### Description
<p>Application Source Code was disclosed by the web server - Perl</p>
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-GEN-SEL/CGU.pdf](https://www.impots.nc/statics/public/infobulle/CU-GEN-SEL/CGU.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `$#ggBG`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/2-sabonner-au-teleservice-vos-demarches-fiscales-en-ligne.pdf](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/2-sabonner-au-teleservice-vos-demarches-fiscales-en-ligne.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `$#0IYk`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that application Source Code is not available with alternative extensions, and ensure that source code is not present within other files or data deployed to the web server, or served by the web server. </p>
  
### Other information
<p>$#ggBG</p>
  
### Reference
* http://blogs.wsj.com/cio/2013/10/08/adobe-source-code-leak-is-bad-news-for-u-s-government/

  
#### CWE Id : 540
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Source Code Disclosure - PHP
##### Medium (Medium)
  
  
  
  
#### Description
<p>Application Source Code was disclosed by the web server - PHP</p>
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/Declarer-la-dns.pdf](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/Declarer-la-dns.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `<?=ÄÓ¡d.`ÍÂ\x000b_¼¤b#÷þP\x000ft±.MÇïZL\x001edÎê¤÷U$Ô\x0007BGJµ@\x001cö¥xñjÈ#g\x0012	áL4ì>Fe\x0004ÚSæ#{\x001f¼H\x0007«:\x0005Ö!\x001béep@n\x000c}\x0014ü¤òzN3Ðcb\x0000åí¯%?h)t²Ú\x00151Ü¼àîkaØ\x0002A\x0000\x0002\x0006G\x0007¾ióI:XùÍpì_Ln\x001a$HÕ¥Ú7\x001bóÔð¹Æ\x0000éh \x000cVuð¥Ü¦lÈ°LÉ$nÇ\x0000nÙ \x0016ÀÇÍß¯9ÍB.\x0002Ç}äÜ\Mn±ÄYÌ\x0015³\x0007\x000cÄ~ï\x0003i`\x0000Ø2@\x0006·';$UÝ\x001cªQ×8È#\x0004Sè\x0003´k¡\x000c\x001e|±Åöó\x00101NÏþÎ_\x001bØ\x0006`IÎ}ÆÓÀ4éd¾Kkæ>,¶[2¼\x0019\x0006æv\x0019Áò6ñÓ{\x001e¼\x000e\x0000ç i§Ò1tÂ\x0019/J©·¸i3\x001fÄ¯À\x0016ùç·@A^#¸º¸[)¶Ï(1Úß;Îw"ª\x001c÷ w<õõ®\x0000«"]>\=ÄÍ¹pò1äð\x000f\x0019ÏAvÆ8¬Ý\x0006å¥»»:´(º\x0015¸yÔ\\x0012\x001d'î\x0008=ó[P\x0006
,i¥MrC\x0012{Ã#ìÚ­pwdÿ\x0000
ð2Ý@\x0004­mvÒ[\x0015vÍo|·\9\x000b\x001f¸~ôá°\\x001eù\x0000\x0012\x0008ÏOE\x0000sZj}¥í"\x0017s4\x000föÇfM¾v'\\x0012W\x001e¹Êãò$\x00165ÅÊi+9º¥¹Ò¦¸tp©´¨\x001c.7\x001fº\x0006{äó]E\x0014\x00013J·W\x0002âlÅ}\x0004HÎÅV\x0011\x0006ùz\x001c=s£\x0007&¢vû"4×J©öÄ·/n§\x0012°_Þ(ì\x0001\x0001{á®\x0000åî\x001bý5Ý.. ¹\x000b/¾ûd\x0000ÌUOº\x000fL`\x0012¼s-õË[jqG\x000bË¹&!æ\>v\x0016PH\x00042½w\x00123µÑÑ@\x001c­´[Ãq\x001d²¼¨	¼È|ÅvðIç\x0004}w\x0013Üæy&\x0005.\x0013O½í·Ú'2ív\x000e\x00031?Ã·åéÏNyèè \x000cí:A\x0014×ví+\x0015àG\x0008Ë1ÌJäd¬{ñì*¬Ò¬ú©q2}Åf\x0011È]ù#¿Ý\x001c\x001e\x000fpp1µ$1Êñ;®Z&Þ=\x000e
çòcRP\x0006\x0005ëÜZ}¶\x0018f@©o#4²\x0011÷¤a!Ýü\x0003jÿ\x0000\x0008\x0001pH\x0002£¦;HÅÓ\x0008d½*¦Þá¤Ì~K\x0012¾c\x0000[æ\x0007Ý\x0001\x0005xèè \x000ezk\x001a~®ÿ\x0000j^$W\x0005£\x000cq\x0018\x0005¼³à;pF1¸\x0012yÆF¯ D¶óehmlO s\x001eÕØÄe\x0005~`£¨ôïÑ¢95¸d³µÿ\x0000HF´ynM%Ù·Wo;å;ÐrH,p0\x000f'µk_\x0019OîMÃoØ·ÛJå¼³\x0001\x001cöÀ­j(\x0003¸ãûqãó\x001cO\x0018ZáÃ4xBØ\x0002\x001crãqéÏ#o\x0016õÉ\x0004~A{?+%ÃÛ«\x001e0|Å\x001dG?/|ü5­E\x0000s\x001aÕôÚ$¨×	2Úc\x0013JbmØ';\x0011pì0\x000b)ù@Ç@MY¼ÇÛ÷Üùq¥â©\x000f+D»|;|ÁÌcqÎ{?·¨ \x000ejêêQ§ïYgÝ²!<©@¬\x001bÃû¬y ÔÔÔ\x0003ÚéxY¥ :	%fù¶\x0017\x001ec\x0013ü?)c£¦1Æ\x0014\x0001Ì$ð¥µóEtÓ[µèQ7Úv&<ûò¨$\x0001drN\x0001''2X<×íc\x001có\F.·"HÊHIUT\x0013Ãp;ðÞ½H=\x001d\x0014\x0001ÌIy#Zi÷\x0013Ü±KXä\x0008³\x0018\¹\x0019%\x0014
²±ãä<\x000c\x000eÍ[\x001aü~iõòßú&J¿E\x0000sÞ\x001fâiÐË2\x00170fá\x0005ÃÊÂL¯ÞR1\x0011ûÿ\x0000(?ËÅÛ@Ö&XHÍº£\x0011æ1fÞ6ÿ\x0000\x0017\x0001sv:Ö¥\x0014\x0001Ï%ãÿ\x0000oÃ\x001a3þòy#<ìÌ\x0014#\x000cxÚí\x0005NrÀgµP7\x0019¥KÇ{ÅÒ®\x001etórÐËÉãª\x001cÿ\x0000\x000f\x0000mà\x000ek°¢9­U®-®	s 
\x0004\º\x0016³äU>iû&08\x0000`âµ5y\x0002%·+ClÓby\x0003ö®Æ#,\x0008+ó\x0005\x001dG§|V\x0014\x0001]}¾U¶ÿ\x0000HÅ´
1u2å
pÇ\x0003#\x0003ôÅkQE\x0000\x0014QE\x0000sRQ^!ë%\x0014Q^Ùä\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x001c¬6³yam ¸øiÓG3ìd\x0006såó¸áK\x0012\x000fÌ\x000f8\x001cð*{kOô;ÝË\x000b\x0008ÿ\x0000w
B\x000cK~í/ØÆå\x0018\x0019<\x000e\x0000ç¾Î\x001bIÚmöD³ä*Ú9ÆÞ¦\x0002w\x0005Éè?\x0007èM8Â+\x0013{dÏf©(1\x0008\x001aE\x000cYv7Wå
~è;x­ú(\x0003¹æ
2á.b¸âãK\x0001±\x001aRÒp%AÇ,9=sõ«w0ã[Y\x0004
,Ðð6å^\x0001)08E\x001cw\x000e+r\x0000j8u$\x0006\x0003$|ÊGCÿ\x0000äÓ¨¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
JZJ\x0000Z(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢9º(¢¼3×:J(¢½ÃÈ
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
dR'aÔ\x0002iõ\x001cÿ\x0000ê$ÿ\x0000tÿ\x0000*\x00001/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4±±xR\x0001§Ôp¨ýÑü¨\x0002J(¢9ª(¢¼3Ø:Z(¢½ÃÇ
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
õ\x0012ºIQÏþ¢O÷Oò 	(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000*8?ÔGþèþU%G\x0007úÿ\x0000Ý\x001fÊ$¢(\x0003¢+Â=¥¢+Ý<p¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¨çÿ\x0000Q'û§ùT\x001cÿ\x0000ê$ÿ\x0000tÿ\x0000*\x0000( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002£ýDîåRTp¨ýÑü¨\x0002J(¢9ª)(¯\x0008ö\x000e(¯tñÂ( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002£ýDîåRTsÿ\x0000¨ýÓü¨\x0002J(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
\x000fõ\x0011ÿ\x0000º?IQÁþ¢?÷Gò 	(¢\x0000æh¢ðdé¨¢÷O\x0018(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000*9ÿ\x0000ÔIþéþU%G?ú?Ý?Ê$¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¨àÿ\x0000Q\x001fû£ùT\x001c\x001fê#ÿ\x0000t*\x0000( \x000eb(¯\x0004öN(¯xñ( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002£ýDîåRTsÿ\x0000¨ýÓü¨\x0002J(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
\x000fõ\x0011ÿ\x0000º?IQÁþ¢?÷Gò 	(¢\x0000æ(¢ðOdéè¢÷\x0018(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000*9ÿ\x0000ÔIþéþU%2E/\x0013¨êA\x0014\x0000ú*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000
\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ\x001b$ÛfXwÈpHÎ\x0002¯©ýp;`Ht\x001fê#ÿ\x0000t*®¶¤lÊÃomÏ÷ß3qÉ\x0018ã°ã\x0006,Æ¥"E=@\x0002\x001fE\x0014P\x0007/E\x0014W{'QE\x0014W¼xÁE\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E`éæDÉ¥k¥^\x001ec7
ÉØIØ7 ãp;G\x000b3ÓÒ¥iô)\x0004cÉ<\x0007©$Äæ-ÑYÚ\x0017	g{zÉ\x0013[À&Û\x0018$6cb9<»i=\x0006:sÖ¦]Ïq$É2³\x0004
V_³I\x0000lç+µòN0\x000esüCÓ
\x001a*ÍÅÂêv¶Ð¶H$ùÈ
È8Ç®â?^Ø96z³ù77æÙ=©¹'É=@+\x001eöÈläà®\x0007\x0004ãæ \x000eÎ¹îÖÐy²[ùÅö«¬NÛ3Ä`'0\x000f@[<b«A©^^\x001bXíÄ(Ò¬ûÞXÛ\x001bªd&Aç'å$\x0011§\x0018 \x001bTW9qsw\x000crÛ2Û\x0012Ê^w6<ÉH#\x0007¦}FAí\x0008µ	_ì¹TýõäÐ7\x0007O7\x0004s×ä\x001f­\x0000iÑ\àÕ§´Ñlæó\x0016BI4bWåÏ$pÁù9çæUðjSÆgF\x000f|c*Ø}°ãw#§\x001d3Ô\x0000oQYÚ\x0017Ú=´ÓHÒÍp3±'«\x0000x\x0004}\x0006\x0007 \x001d*¦«]ÝÇæ%³J$·3ÆKÄ\x0015¸Ä{Ûålçï\x000c\x000fsÀ\x0006å\x0015qyy5\x0011ÜÄ²­Ä\x0003q·&ÃH\x0006
1\x0007\x001eùÁ\x001b\x00063Z÷×\x001fc°¹¹Ù¿É¤Ûg\x0000gð \x000b\x0014VtÓ^Âð³[æ1¬¡\x001bh\x001b\x0019òS9þ\x00121»ß=ª\x0004¿½¸Þ\x0008~Îâq$¬@1H© ÷Éã<g©Ç \x001b\x0014W8/îg¸K½Ê±µ½³Ã\x000fÍi¦[\x0004\x0007Ç\\x0011é§$ÛkûÐél¿gkµ}¤*ÁHòLä8\x0018Ï8ê3À\x0006Å\x0015ºû²m[P³\Ëm\x0018!²»KüçxB6÷<î\x0019Àl´ûmã]©+:ÛÉ0>S8E9\x0019Îy<tç9 
Ê*\x001bI^{Hf&äEfº¡#$\x001f¥e­é\x001aä`o5Ü\x0018â\x0000\x00143s'Ýr6·\x0019RÌ3ÁÈ\x0006Õ\x0015Vöáí	\x0000S\x0019#=pÇhÇü\x0008®}³Þ²ÿ\x0000µîÖKÄ+\x001c6Âð«)&HØ¹UÎ~VÚ'æ\x0019=8ä\x0003zÌöâ=HDÁ#rªïÈ\x001csæ\x000fNI\x0001HÉ tÜ1~y<¨$(6)lÈÛWÜö\x001eô\x0001%\x0015ÎO¨ÞO\x000cÇ2¤±Íl|Ók$Y\x000f.Ý»\x0019³Û\x0010Hã­\x0010j7C\x001c2L¯,\4ZÉ.\x0002K·nÅl÷àç\x0000\x00009ë@\x001d\x001d\x00156«z#e(\x000b(îä@Åòw\x001fl}Þ§§¡Ï\x000c{û»[ÕiUÄ¢\x0018äò\x001fî©Ëp1Ioj\x0000ß¢±ÛP¼6pH"hK\x000f#ZÉ'Ýl/îÆ\x0018n\x0019nzc\x00079\x0006µ Í92zÌm¹y\x001dqï@\x0012QYw\x00172AzD\x0002[ÀT>JÏ ÈQÉ=8\x001c±\x0000f¥Ò¯^ò9Ä/\x000c¾Yo)¢Ýò«gcr¿{\x001cúg½\x0000_¢²u
BêÞ{¿)a0Ú[-Ëï\x0004³òùQÎ\x0006BuíèsÁ6¡tÞíXDpÏ\x001d¼dIgòù<ô\x001bÉÇ~c$\x0003ZÉûuÖï²æ\x001f´ý§ìþnÃ³ýW³ÓåÆïj¯ªßÌ¬Fß|D&$IKaA\\x0005Á^\x000b\x0003É\x0007\x0003m\x0000oQX·÷wM$"\x000c7Büç-\x001b\x0012\x000fLaöíÇ©Ïj-BWû.U?}y4
ÁáSÍÁ\x001cõù\x0007ë@\x001atV\x0002j×i`ÒyQËw	1ÛÉ8P\x0002qµNyÝô\x001d9ë[6¼öÍ$M\x000bÈÍ\x001buBFH?J\x0000Åû]Ô×ÖO[g¼-ªHoe^{0%sÛ\x0018\x001dzi\x001a¤÷òF^6ò¦Î\x0007ìòF"û¸]ÍÃçqäcî9à\x0003b©¨Ï<\x0010+@¹%°Ïå´\x0006\x000f;\x0017ç\x0003\x0003¦sÐ\x001a©.¡0µ·d\x0011$²V	%'iÇ\x0011®\x0018{äü§åç9 
j+\x0016-JyÑç\x001fìíæ\x000b}»Ëäà}í g\x0000\x0002ØÇ¦$öY\x001aÈ;#³\´lU^#)Û'*x\x001c\x001c`÷\x0018\x0000Ö¤¬#TþHËÆÞTÐùÀýHÄ_w\x000b¹¸|î<}ÓÇ<[»¸¸[¸-í[Ý\x001eRdÎ\x0008R£o\x001d3¿ïst4\x0001vÀ´Ôî#Ñ^C¶GKä3är¯Ç<ýÁùÝ9lªø;K\x000c{ddgó \x0007Q\Õýä:YÌI\x001e;4¾È\x0019»Ã\x001d«óa8NÀ\x0014t«·:ìr^\x0018Ü¤\x0017\x0011@\x0002åü¼äöÆóÎ\x000fQÇ\x001f0\x0006Å\x0015/ïcA/ÙÙ-î#·rªÀÈ_f\x0008\x0019;vï\x001dÛ8?v¥PþËOß^M\x0003pxTópG=~AúÐ\x0006\x0015Î
Z{M\x0016Îo1d)dH¦)%y>\òG	\x001f³xùNmË{r·Cn"Ü÷¢\x000cÈX>Î\x001f8Ïb:\x000c\x0003ìI4\x0001±EcÚêÏ¨\x0008Äla3I	\x0002ÞAåìÜ7\x0019>ëd®0\x0000Æî¼sgYÝö\x0010ªîç	G*pePFG#h\x0002ý\x0015©ÓàºÞi¶=ó\x0002ò³²:\x0005\x0000«\x0012HûÞ½1Îf73-í¤Ò7\x0007y\x001c	#1Ë°qü<>e8\x0018Å\x0000lQX:y&²iZédÍæCrv\x0012v
çh8Ü\x000eÑÂãâ´õ;¦²±irÛ\x0007Ê[\x0005.p98Îp98Å\x0000[¢±×P¼k'q\x0013nY¼³1µ|»AÞ"ûç·\x0000ûô\x0018¢\x000bõ[\x0016óâ0µ¼ÅÑ\x0011â®8'å<\x0008%~a
*£qq\x000bZGl"ßq13\x001b\x0019³Ç\méß¦Fr+Zê\x0017O-¿°ùrÏ%¶\x0010\x001cMù~O\x0000ùdmç\x0019\x0007qé@\x001aÔW=6±1ñII?Ðå\x001a8äWh\x001c\x0007$yîûËî1nMBé.®\x000eØ~Í\x0005ÌPc\x0007{ï\x0011óà`¾{ç§\x001dH\x0006µ\x0015ÎA¨ÞA\x000cpÉ2¼²Mr|Ñk$¸	.Ý»\x0015³ß\x0000\x0000ç­O6«z#e(\x000b(îä@Åòw\x001fl}Þ§§¡Ï\x0000\x001bVMæ§-½ú (Ñù±ÄQav9r\x0006LåB7gi\x0004\x0007?0Ãb¿½DÝöuI®&¶
Äf\x001cò?¹£ëÒ6(¬í\x001d®%Ð,ÝåV¸{uo1JðHÎOlóÏµdÛj×éöó\L¶QÎÛmä¦Ý»\x000b'aù~ñÎIÎ\x00061@\x001d=\x0015s¨^Ç%á-ÊAq\x0014\x0008\x0018°._ËÎOlo<àõ\x001cqó\x0002þö9$\x0012ýÞâ;w*¬\x000cö`·nñÝ³÷h\x0003bÅòòY¢··òPÈ×EPÏ´G0Qs\x0000và`ÖºÕâ;wKfb¶ñ^\x0008D2Kæ3nÂex\\x0015à°#$\x001c|´\x0001ÑÑXòêNH""!d[y\x001bvà¤·>UÀ|àáëÏ\x001b\x0014\x0000QX³Í*}§O\x0012¿,ê±6ã¿Ë,Ì\x001b *\x0016m¾\x0017Æfþáîafò¾Ï=Ä¶êNå)¿æ-\x001cùg\x000f½×@5(¬5+`±u$âÅ®|°vîp#Âz\x0003¼õö©ôÛ©n<ÕDvL\x001e xX\x0003¨ù8ãÎ\x000f#· \x0017èª\x0017Ý\x000bû{[S
ù±Hìò©m»J\x0001\x0008ÏÞéë0i>¯q%¡º""²KÉ\x0011Ábá\x001d6ãaç\x0007¯N9\x0000Ü¢³%Ô%OµaS÷7À¹\x0007+$ó×ç?¥TmjuæDªá\x0019Òù@ \x001c²²\x001cu#o©À\x0006õ\x0015×úÙ;ÂbYÌq¬¶²'Ú[h+µK\x0002½Á'#å'
mF\x001cF¢FV|
ÅF\x0001=ð2qùÐ\x0003¨¢\x0000åè¢ð\x000fhê(¢÷Ï\x0014(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢"]@eÆWÜg#ó 
ÐiÖÐJ²F¯ûÒ³"vùT/\x001cp\x0006\x0001ÇJ\x0008c·8"]±Ä¡\x0011s\x00000\x0005sÚLóÃa\x000eëÍÖÚd3ñ\x0006Á!úã\x0004¨
8\x001c£¹pÔ/GÚíÖYVhØ\x0006¹XÉ&Ò\x0008ã\x0018Ç\x001c\x001eO=(\x0003dXZ%%I\x0015`Ù+÷SÀÉäã©äæmi
®ã\x0010rÍ´4@è2ÄrxéÉõ¬×ì$öé;Èñ\,Lëå\x0007ùr\x0002\x0016Éôû ÷ææê{8#¼xÕâÊÞRïÜê\x0018\x0012A \x0010yÀä\x0010\x0001¬a§IÊþñ\x0015[=\x0001 ÿ\x0000Ê M´xX·+©M®ÅÕTõU\x0004«ÓÀô\x0015ºäV	w$#Ï§Év#Ù!\x0000wÇÏÎIéÆ:TwFòX\x001e	¥º$ö¬­)Ë\x0007ÈÚ0\x0008ÈÎAê8 
¯ìëo#ÉÚøÝ¿Þfìc;ó»8ã9éÇN*»h¶e¾Äò¢e\x0008¥K²±*À½\x0008ÀìÄtâ¨éiK-ÖíÌm-ÜnE%¶Î\x0000\x00001ÿ\x0000¼q1.{{s%»Ü	Dw\x0016þwïL@\x0003òãË
wmùÞÉû¼ç¨\x0006ºm¤¨ÈbÚ¬±¦#b\x0008K \x0018#\x0018'µ\x0003N¶\x0017Kr\x0015ÄÅÔy­°1\x0004\x0012\x0013;rryÇrk3^yåT9¼¸à±ó
í\x0004I¸H\x0008=ú'\x0018#ÎzS¥àßÉ\x000c\x0012¬>eøF¤íû0cøäpNz\x000e b.Ë£ØM\x0002A$\x0019"\x0010ÞÀ\x0014\x0003\x0000\x001e~lu\x0019Î\x000f#\x0006¥\x0016\x0016âèÜlo4¸;Û\x001b\x0014Î3ºqùz
Í´½½PBÂQ\x0003ÜK	Þb\x0011á7³å¾Aä}î1A+Ïy¢ÛK%ó	&{IÊ"¦è÷È¼\x000e\x000fË\x0019Ê8 
ø!Þ\x0008àvÇ\x0012EÎp\x0000À\x0015\x0004Zm¤[ÂÅ¹]Jmv.ª§ª¨$^\x000c\x000e\x0007 ¬ëKÛÙu\x0004,%\x0010=Ä°æ!\x001e\x0013x\x001b9Þ[ä\x0019ÎGÞã\x0018Ã,%Ô.cÓÖKö\x0006òÔÎì± )·f\x0002qüç=8\x000bØ\x0003Kû.ÔÀñ2ÊÂB¥¦rÿ\x0000)Êüäî\x0018<\x001f_SVäD6EWF\x0005YXd\x0010z+U¿\x0008æ\2ØÅt|¿-cÜÁ\x000e\ä'Ëü'8Ï=*Ü·7iuu ¸ýÔ7À°ì\x0018!ÄA²zÿ\x0000\x0019#\x0018ç®G\x0000\x0002ÿ\x0000öu·äí|nß¿Ío3v1ùÝqôã§\x0014ø¬à¢hãÃD¬rIÃ\x0010[>¤	'ýMTÐchìd\x000f+Ê~Ó?.\x0017?ëXv\x0003Ó?R{`UE¾¹\x001a*\ùþl÷\x000b\x0003ùjª\x001e?5;sNÝÝÁÉ=4×M´X¼µ	å$Cæ9
)	$\x001e¹ïÅ,V\x0016ñ\x0008ö£\x0013\x001b\x00033³1b¥rI9?)Ç9ã\x001e±íw3Y$×\x0017\x00104w¬OdÁ-´\x0015\x0007\x0007N\x0008ã85ZÚîú
.Ö;s34ø§\x0004\x00182Á¸¶>A´\x000f\x0007\x0019ÉÎ
\x0000tg\x0002ù{cÇ+L¼\x001d·n?øû~tÇÓ­\x0002ítÃ;VF\x0005æù\x0007\x0004ó\x000fAF§4Zn¶»Ë\x001c[±¡ÝT2\x0001ã<gÖ±dkÝ±/p×\x0017ÞKDÞËöunòg
\x0001Ï\x0007\x0001Æ\x0000:\x0018<¯"?³ìòv/ËÆÝ¸ã\x0018ã\x0018¨\x0006h.äEûÔbêw\x001c)  g\x000399ÇSÉæ³òêE·In\x0016ØG¶7ú·U\x0001ðvô9m¤r8+CÊñÍ¨,O*É-ê¢UK·î\x0010áw|£NO`GR(\x0003bxc¸H%]ÑÊ¥\x001ds0ECsaou yÆÓe\x000e=\x0018\x0003\x001c\x000eG'ÔÖ^}s~ú~ÙöÆë;9Ú¬d\x0011Êª¼\x0001 òG\x001cc(Þ_Mqe{\x0001fI´ùnC²Ä\x0001Q\x0014Q\x0008À¿Î1h\x0003¢{\x000bw¹\x0013²6ü ;\x0005b:\x0012¹ÚHÀÁ#<\x000fAV$D6EWF\x0005YXd\x0010z+\x0014K:ÜËj²/D&eDßl\x001f=0I+Ô\x0003\x001c`âòê{kqvÑ\x0002.D¨¥ËQO#\x0000úñO\x0003\x0000]þÈ²Ù*ùovos+ïbrÙÎAïô\x001d\x0000¡të)Q{ñæ»nw\x00041?8\x0004\x001c¸r£¢\x000bÖ}\x0006;éY"f¶\x0013;m,¨väg$\x000fLæ«h×\x00125õõ´]Ñäc7æn`Ã/¸Ï?(\x0002óXZ´rÆaPÂ e\åá@\x001d>ñéëI&m#Ìì®\x001eV\x000eÌ²²Àm\x0005p~S	\x0018ÈàÖsÊñÍ¨,O*É-ê¢UK·î\x0010áw|£NO`GR*îv×Úds¹ÜK:ÊB¹PNÞ2@\x0019Ç\x0019éÅ\x0000Húu³E\x001c{]\x0004yÚÑÊÈüòrÀry9<O4ømüÙöÃå$i\x0008\x0018TÚ[Û@ÿ\x0000çgáí\x0012òYVS6q0FpÉ_B½0\x0008'®IÏ\x0017®®ï#mFDb¸Þ(\x0017pÞ"É\x0004ðOÎq2Nr1
Ilà¥i#ËJªrAÂW\x001e\x0012H#ý\x0005\x0016pY«­¼{\x0004½ù$³`\x000c{\x000cç¦²â¹½uÚI%¤º0ùå\x0019|£';räc§ÝÇ\x0019æ j2Î.V`écÑ\x0014ÆwLFW}Häãw^\x0006\x00005&Òà¸¿{ÆýÑ${y\x001c\x0002ÄAåNá<\x001c\x000cæ§{8\x001dgV"v\x000eü\x0000\x0000AìFÕÁ\x001d\x0008ÏZÏêá®måi{©­Ì%Wjó0G\x001b³û±9<tÃt·þÏ77\x001eq»³3·È\x0014!\x001e^1]ç9Ï#\x000e(\x0002ÿ\x0000öu·äí|nß¿Ío3v1ùÝqôã§\x0014K¦ÚK°4[U\x0014&ÔbÊ:+\x0000@eëÁÈäúÌ×y`Õ!o.8,|Â»A\x0012n\x0012\x0002\x000f~Æ\x0008äóé¯o´æ\x0011|n"¬B"\x0018!;²wîùÎ6ñ÷x<ä\x0003Fm:ÚyÄÎ¯¼2¹\x000b+*³)\x0004\x0012 àÉ\x001d¥\x0003N¶\x0017Kr\x0015ÄÅÔy­°1\x0004\x0012\x0013;rryÇrj¤\x00177\x001fÚ@M3ùrJñ¦\x00024-Ä*ó\x0001yÝÆC\x000fJS{$1Û´ 0feÇæc\x0004	>]¼÷É_z\x0000´ëf\x0008Bº$
\x00123\x001c¬«1¸\x0010qÀã<àzUÑ#cU\x0011@UU\x0018\x0000\x000e
À»Ô®ßç´g#³ä<b4ËnåüÃ(èr\x00019=*ynnã»»Ü¢ÚÜ¤m\x0016À\x0006ÆDÜÌÝ@Rû¾ç6_\x001au°º[®$V.£Ím ÛÎ;Kmaok!xQÆÑf\x0008=\x0014\x0013\x001c\x000e\x0006\x0007\x0003ÐVB]Ý¯ò\x001f.i¢µë\x0018\x000f\x0010g\x001bzrT\x001c\x000cñrEOwst²ZÛA4ÓYYä¶\x0011\x0007%\x0019W\x0007ËüD\x001csÀ\x0003"5.m¢º$¡°\x000eå*ÅYO¨`A\x001c\x00128ìHïQ>hñG\x001bE8ùX\x001eX1ÎX\x0013É\x0007 ¹¬É¯®Ì\x0010\<¾Z-²M)¶òÝPK\x0017\x0004ä§\x001cl98nzU½z6NTY^ óÂ°)Ü­"©\x0007 `ôïß# X]6ÑbòÖ,'\x000fä*d¦\x000er\x0008$zç¿\x0014±X[Ä#ÚLnd\x000cÎÌÅÉ$äü§\x001cçz
Êç[H¡´
\x001a	®\x0007h±,YH\x0018\x000fòí\x0003¯|õ5f+É..£+x
Á\x0004¡¼¼,ÆFaÈ<º6r	çwJ\x0000¹maok!xQÆÑf\x0008=\x0014\x0013\x001c\x000e\x0006\x0007\x0003ÐS®m!ºØe\x000e\x0019sF=FT\x0007\x001d8\x001eº£Y·K+Åq4
Ë\x001aÇ
£;ò
Iã¯ªÓ?´.c1¸TgÓåÙm.¾YÉÀÎ9lØñÎ(\x0003B]"ÊX\x0012\x0006Ö4Cµ%tÜ`+`Ã¯\õ>¦¯ÕM6i.-Úi\x001bæi\lÇú°¬WoÔcHÎpq¥ª]\E%ëC3F,­EÀPªDïá²	ÇÈ:`òyé\x000bgJ³1Å\x001fÁ"A\x0010Q#\x0000È:+\x0000~a×ÏSêjV³¼ÍÑçÌfnO.»vüq*£5äëöÍ²cË¾\x0015àpån\x001føû~u­@\x0015ÚÎ\x0006ó7G2U¹<ºíÚñÅü©N¶\x0017Kr\x0015ÄÅÔy­°1\x0004\x0012\x0013;rryÇrk\x0016\x000f2ßJÒe¶ó·pA\x0003y[7\x0005XÝÁ]ÿ\x0000.s×=ºsVaúæ[8\x001aá­Ë¥Á¨ìUy\x0019PØ<ã#08À\x0005Ùt{	 H$1$B\x0010Ø\x0002`\x0003ÏÍ£9Áä`Ôÿ\x0000cÎó|¿Þy¾vr~þÍÿ\x0000¾x¬eÔï\x001eÖ[Á"*Å¦Gwå\x0004á¤eõë·å\x001cuàr9ËÅÝôQÏ\x001ce; Tk\x0011|É61Âq9\x0019\x001dsÔ\x000cP\x0006¢X[¥ÉQ·ä°\x0005ØªÔÎÐNNH\x0019äúêÚ+¸\x000c3\x0006(HoA\x0004\x0010A\x0004r\x0005cÛÜÌ÷±Å%Â\µ\x0006>ÅÈ\x0002ÜqÑ³r8\x001cUk¹îeÑïÒââPÒÙI*àFÑ¸\x0000dÄËÎÎ@ùþb\x0018`
\x0000n.l°O	WtJHdpF7\x0012N9<gZ[hf\x0019¤ZX	1¿uÈÁüÁþ^=Íì\x000b~Âáå\x0010Ï
´j\x0011\x0003â,¶x\x001b¾c\x0012s\x0004¹¿"\x00033Âíxa- ¤Ùäùü¡³ÓÛnAç \x001apiÖÐJ²F¯ûÒ³"vùT/\x001cp\x0006\x0001ÇJxc¸£w#{àÔ\x0010G È#j¯q<)m\x001d¸´óygÉÙ¼
ß.ÿ\x0000øG^Ùï©\x000c÷×2ÙÀ×
n].\x000cDlçd«ÈÊÁç\x0019\x001cÆ\x00004³­¼'kãvýþky±ïÎìãç§\x001d8¥K\x000bxäÑ\x0019Z\x0000Á\x0008vþ,nÏ?6H\x0007óÏZÏ¾Kß\x0006ÍpíåÉ5¶\x000e2S$s\x000fO\~u\x001dÝôÖ·±*Ï4ª³ÅlÙX\x000b6ÜèÅðÛ¾P\x0007N84\x0001µ$1Êñ;®Z&Þ=\x000e
çòcQ­\x000båí\x001e\­2òxvÝ¸ÿ\x0000ãíùÖ\7\x0017$EîÛmÅÔöÁU\x0014yj¾a\x000c8åÀ9ã\x001dæc4^
á\x001bÌ\x001b\x0011*ï\x001cd&@ã\x001c\x000e¸üè\x0002ØÑì\x0007ûõ4'çn#le\x0007</\x001c\x0001Àç\x0018É©ÚÎ\x0006ó7G2U¹<ºíÚñÅü«%îîmîîmÅï"k@	UÜ¾d¤0l\x000cd®;\x000e1ßë»ë¡4ÐÄeb×¢\x0005òBoUò\x0004.ï®zö'Ú/.Ô©\x0001eR]¤Ü:°,rØ ä\x0002yÀã<âÖ\x0016­\x001c±T$°\x0019W yc8P\x0007O¼zzÒiÍ5µÇúÀÎ§%IÀb\x0006v7`\x000cãç§JÀ³½¸¶Ð!h®PÚ\¦\x0015q\x0013F¨\x0000\x001e¿xç9ävé@\x001bói¶Î&-Î\x0019\|Ä
ÊF\x001b\x0019Æî\x0000Ï\qÓzÙÀ¾^ØñåÊÓ/'mÛþ>ßeÞÜ^[­çú[n²µ\x0017?*(YX\x000eÖ\x0004\x0012\x0014l\x0000`rIæ¦òuûfÙ1åßA
ð8Fò·\x000fü}¿:\x0000Ðµ¶ÒÚ;x\x0003,Qª\x0019`zdj²é\x0016K\x0014Q\x0008ßËv\x0005ó_\x000c½¹ùdðÙ\x0000\x0012;Ö%ë´¹$(?eÔÊ tGoòkJ{«¹¸feH.¡·\x0010]¬\x001fËÉ<nÏï\x000e0@àq× \x001a
g\x0003y£Ï*ÌÜ]ví?øâþT5
æn>d«3ryuÛ´ÿ\x0000ãùVm­Íß\x0003Ëqæ$×Ûö\x0000\x0015TÈAÏRß \x0019Î1Û<ÕMîDÇnÒÁ\x0003\x001fq\x0010$ùvòsß%}è\x0002ÌVpE"É\x001cxuó0r7æ@5\x0011Ò¬ÌqGå0HD\x0014HÀ2\x000eÀ\x001fuá³ÔúO¸ûEü\x001d$G³·:Ç·vã'<ó8\x0004ñùÕK½BòÜÝ¢òÖ5ÁvN\x001d\x0002å\x0014Ã.FsÏÞ§\x0000\x001aan÷"vFßÄ\x0007`¬GBW;I\x0018\x0018$gè*Â E \x0016#$üÌOSÿ\x0000äV<×\x00176KoökZ°E]Øb¼\x00001ôÏ't÷7L÷qÅ#enj#Ø$Ûä«a7|¤äsÛw  
C\x000cm:NW÷¬Ùè	\x0004üt~U
X[¥ÉQ·ä°\x0005ØªÔÎÐNNH\x0019äú4ùLÖhÌìì\x000b#\x0016P­b\x00088ã \x00128$dqX©Ý´°É4Å­Ú\x0006Hÿ\x0000xªÊ@W,ªà°ùòG\x001dÁ 
ô«8äf\x00111\x0005\x001a-#2\x00048Ê'h\x001c\x000e\x0000íRÛZCk¸Ä\x001c³c-$#\x0010:\x000c±'\x001c:r}k"KëÙ¦a7\x0006;4öq\x0016àQ\x0014ÿ\x0000)VÉlõù8\x001cËo%ÝÕÅ-ã«\x0018£æ$\x0011J\x00058$åîx\x0007òä\x0002íÞ\x0015åÜ\x0013Ê[\x0010£ª%X\x0016+È`A\x001c)\x001cu\x0004Ó¥Óm%Ø\x001a-ª\x0013j1Ee\x001d\x0015 2õàär}MVÕn.VîÚÚÜ\bDF6þ^ÿ\x0000 \x001fë>\|Çß§½Rúý ãÏHü>;£\x001cj¬­!\x0012\x00127sò\x001d½¹é9È\x0006´Úu´ó_xer\x0016VUfR\x0008%AÁ#\x0003;\x000fJ{ÙÀë:´y\x0013°wää°\x0000\x0002\x000fb6®\x0008èFzÕhgMJà5Â¤qL XH\x0018Ý«ä\x001e»¹=ñÓ<ÖiÔ/#Ó\x0005ÏÚ\x0019ãNì\x0002«U\x0008\x000bÓç?{=\x0007=r\x0001¨úE£¬`\x0017\x0012\x0006,F2X6IÇ\x0019'ÇJ»\x001a\x0008ãTRÄ(\x0000nbÇñ'øÖ\x0016¡u¨[Í,Q<²µ½¸º\x00082Ì_Þr\x0010m\x001ftç\x0019É'\x0006·è\x0000¢(\x0003¢ð\x000fhêh¢÷Ï\x0014(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000¯\x00046¶¬±A\x00140±^\x0011\x0014)*\x000ez\x000eÀ·æÞôGek\x0012\x0004Ú\x0014A*Æ\x0000à\x001f$sæá¸ìÞéæÔF;É\x0016ï1£÷yùy*wq·§\x001c\x0001ÍY¶ÚÎõ£»[¨
\x001dÔ
\x000eã¿2Êåp\x000e3°|Üw\x0000ÝÖÞhäX"%!Y\x0001\x000eF0HïÐ~BÅ\x001f²$_-v&\x0014
«Ç\x0003Ðp8ö\x0015KEKhåYUÈ
ç\x0019ð\x000fÉ!\x0019aÏ~# \x0015¦Å$Ñéi-åÛ«#4ß¾ ¹\x001e^ÞG+çîà2O9\x0000ßHbËÙ\x0012/»\x0013
\x0006Õãè8\x001c{
ÙXCjÐ\x001bkXíèÌj\x0011\x0006GBsÒ°¤½K\x0008æåÒå´ø¥µ\x0002Blä1 (Às.\x0008äqÏ2êR¡½'ºhæ\x0017¶ë\x000c&Lyî!ëón;ÏËà\x0011@\x001aÅôÛ57%­-Ã;)\¹?0Ï®W÷}ªxmmàI!(ÞSºFD\x0000¹õ$uê:ænËçÎM\x001d¶£±¬6í\x0005ã8à\x001fÐz\x000clC(:ÕÂK<«2¸\x0011D\x0018á¢òÔä¯LoÝóú¹í@\x0016¯ml§Ì¾ÞD\x0016Ý2)\x0008;?JRÝår«\x0013H¹\x0003*û@É÷Ú@ú\x001fJäî.ZâÚþ\x001dòùoa<¯ºáÝ·®Ü\x0006\x0018\x000b\x001b\x000cÈ§\x001càb´ZuÌ®X}±Q¥óØ\x0005ìêËûÌä\x0002ûyÏ$÷Ï \x001bkkn/r°D·\x000e6´¡\x0006æ\x001cpO^Ãò¦µ«E,Mm	Vß"\x0018Æ\x001dºäçÍd[	.ç²K\x0001K6JWÌE\x0004d°äü¤\x0010ÀäúNkÉy#Zi÷\x0013Ü±KXä\x0008³\x0018\¹\x0019%\x0014
²±ãä<\x000c\x000eÍ@\x001bí\x0005´2Ëx A1_D.Àvàdô\x001c{
t)ncH\x0016"bd\x0003\x0001\x000e8R;p:z
©­J"´BÌÈ¬à\x0016ó(8'ç\x000c¨ã·SÐ­g%ÕßYã/ö¤i\x000cJXJHv¡-AÚ\x0014ç\x0004ç\x00064ÊÕüÖÐ·Ùñåf0|¾wÓ ééR\x0018b;³\x0012\x001dÌ\x001d²£\x0018Á>ã\x0003aT-¦ô»ÒÓ7¾XÄCs\x0004Æ\x0013båB¶\x000fñ1ãµc-ì¾EâE;¤HÖ¥^	ÞäüÒÅY-À\x0003\x0003# ¹\x0014\x0001ÔE\x000cPïò¢H÷±wØ ncÔSïM\x0016¶ë\x001c±¬\x0011\x0004B\x000c9=I\x001dóïX\x0012\(HÞL,
öÅ%fÝ\x001fK|ü»÷e³òàò6ñ Lvúéâ²?hÛ)£
\x0000ç\x0004\x0013É\x001cüÃq\x0000×k[(m4\x0016ñÛÛ5AE\x000b\x0019\x0019;aÜæ§Ù\x0005\x000b;p ;¢\x001eRþìç9^8ç+»\x0017\x0017zeá¼á]4åx\x0014\x001eaY2H\x0018ôÆ:zMÄ§U	
Âm\x0012Ä-Ë]¹gj\x0016"0\x0008\x001c¿ÎO\x001c¹\x0000\x001d\x001cFÑÈªèÀ«+\x000c\x000fPEW]>É-ÙlíÖÝÎæD»XñÉ\x0018ÇaùUm%±\x001c²MpîòÜÍ\x001a	\x001f\x0016GÂ¨ú\x0002}qì\x0000\x001at\x0001	µ·hâ ¤$4jPa\x0008è@íj%µ·9#\x0008¤IHgV@C\x0012;ô\x001f©¨ \x0008Ö\x0018$H¬7`\x0000Ç-ùO©¨Å¨ó1m\x0008ó7oýØù·cv}s\
±E\x0000W6V¦\x0006ÛBalnÆ6\x0000\x0006GN\x0000\x001f©\x0012\x0018£òöDå®ÄÂµxàz\x000e\x0007\x001eÂ¤¢\x001b\x001a$q¬qª¢(
ª£\x0000\x0001Ð\x0001QÁkol¸·(F6â4\x000bÆIÇ\x001eäÄÔÔP\x00042ÚÛÍ\x001cË\x0004R$¤3« !ÈÆ	\x001dú\x000fÈT\x001aª	-\x0018äøM:\x0000ª4û%Y\x0016ÎÜ<À¬"\¸=A8ç>õ3C\x0013,ªÑ!YÖ\x0002£\x000fÆ9õà\x0001ô©( 
ÿ\x0000bµû/Ù~Í\x000fÙ¿ç6uÏNy§=­¼	\x0008P\x0002ïd\x0005°\x000eà3ì@?Z\x0000mmÒåîV\x0008áÆÖ ÜÃ	ëØ~Tä(ü½"ùk±0 m^8\x001eÇ°©( 
÷6V·~Õm\x000cû3·Í63×\x0019úSÖÝîRå ®\x0010mYJ
Ê9à\x001e½ÏçSQ@\x0010­­º\½ÊÁ\x0012Ü8ÚÒ\x001bqÁ={\x000fÊ[{¸Äw0E:\x0003¸,\x0018\x0003ëSQ@\x0010Íko<É4\x0011Hñ\x001dÑ³ %\x000f¨'§AùS\x0018eV
Ëþ°\x0015\x0018~1Ï¯\x0000\x000f¥IE\x0000FðÅ'¾$o1v>T\x001dËÏ\x0007Ôrx÷5\x001c¶V³@Km\x000c¦6Fñ«ÐqV( \x0008fµ·Hä\x0008¤xèÙÐ\x0012Ô\x0013Ó üªGD@uV\x0000Ã\x000cò\x000eAü\x0008\x0006E\x0000WÊÖx¼©­¡=Åö<`Ç$\x001eü}ÍHðÄòÇ+Ä$YØåA)\x000e\x000flÔP\x0004"ÖÜNg\x0010D&b\x0018É°n$\x0002\x0001ÏÐô&£]>É&iÎÝes¹D»ä6IÇ¨\x0007ê*Õ%\x0000AöH¾Ú·@m+)À\x00006í¹'Ôü>é­mç9&)\x001e#º6t\x0004¡õ\x0004ôè?*\x0000¯-¬Ó¤òÛC$É<`²àä`õ\x001cÓ­­ÒÚ&\x000b\x0010]äù½Y\x001fÔ\x0000ímä¶\x0016Ï\x0004Mn\x0000_)\x0015Àè1Ó
rC\x0014~^È|µØP6¯\x001c\x000fAÀãØTP\x0004qÃ\x0014Xò¢DÂ\x001bT\x000fg\x0003è2p=ê\x0006Ó­ÖÊ[[xÒÖ9~ð4\x0000ç¯\x0004\x0010r8ät«tP\x0005K=>\x000bHÂ¨ó\x00186ýîª\x0008;v\x0002\x0000\x0000\x000c(\x000bÀ\x001c~4õ²µO?m´+öù¸\x000f3¯ÞõêzúÕ(\x0002\x0015µ·H^\x0015%ÆÖ@k\x000c\x0005Á\x001f@\x0007ÐQ\x0015­¼1Ç\x001cPE\x001aDK"ª\x0000\x0010äÛ©üÍME\x0000G<1\DÑO\x0012K\x001buGPÀ÷èhHbËÙ\x0012/»\x0013
\x0006Õãè8\x001c{
\x0000ÉÈò<¤òvìòö»qc¦1Ú£\x0016V¡´;U\x0014ùc* ä\x0001è\x0001\x0000ê*Å\x0014\x0001\x0018!·\x0011 ÚÅ×å\x001c1ÎH÷9<û +x("H£^\x0014\x000eý\x0005IE\x0000TNµ¥òáEX&(	´\x0016=1ßyÍ*éöIlöËgn¶îw4B%ÚÇHÆ;\x000fÊ­Q@
\x00128Ö8ÕQ\x0014\x0005UQ\x0000è\x0000¨RÊÕ\x0016EKhUeP\x0004`\x0007P0\x0001õ\x0000qJ±E\x0000C5­¼òG$ÐE#ÄwFÎ> \x0007åMÊÖiÒym¡dÆÉ\x001e0Ypr0zjÅ\x0014\x0001	µ·e Á\x0011\x00042Pr\x0018åây>´5­»Ü¥ËA\x0013\ Ú²\x001bsÀ={Î¦¢#\x0010Ä6â$\x001bXºü£9É\x001eç'sM¹µ·»Gs\x0004S ;È>¸55\x0014\x0000Ð$2\x0005Pì\x0002Ç$\x000càgñ? "	\x000cT;\x0000¥±É\x00038\x0019üOæiÔP\x0005x¬­aàÚ\x0018á|ï#\x0001[#\x0007#¡âº}[=²ÙÛ­»Í\x0010v±ã1Ãò«TP\x0003cD55TE\x0001UT`\x0000:\x0000*8ímâ¤\x0008Ø³\x0016T\x0000ØÉÏ¾\x0006~¦¢+Ëek4	\x0004¶ÐÉ
cdo\x0018*¸\x0018\x0018\x001d\x0007\x0014×Óì¤¹\x0017/gn×\x0000óZ%-Ðç\x0019ã\x0002­Q@\x0010ÜÚÛÝÆ#¹)Ð\x001dÁd@À\x001f\\x001asÃ\x0014fø¼ÅØùPw/<\x001fQÉãÜÔP\x0004~L^å'·g´nÛã=qÕ\x001aÙZ§¶Ú\x0015ûF|ÜF\x0007×ïzõ=}jÅ\x0014\x0001\x000cÖ¶óÉ\x001cA\x0014\x0011Ý\x001b:\x0002Púzt\x001fME\x0014\x0000QE\x0014\x0001ËQE\x0015óç´u4QE}\x0001â\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x00056D\x0012FÈÅ`AÚÅOàG#ð§Q@
\x00128Ö8ÕQ\x0014\x0005UQ\x0000è\x0000¦Í\x000cs IWrW\x00038åH`0*J(\x00029!WÝrÑ6ô9èpW?\x001a(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¤¥¤ \x0005¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0003¢+çÏlê¨¢ú\x0003Ä
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(¢
(®\x001bÆw×VÚÄI\x0005Ôð¡·S¶9YFw7<\x001f¥\!ÎìTcÌìw4Wkj\x001fô\x0010¼ÿ\x0000¿ïþ4kj\x001fô\x0010¼ÿ\x0000¿ïþ5·ÕßsObû³Ey7ö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGÕßpö/¹ë4Wkj\x001fô\x0010¼ÿ\x0000¿ïþ4kj\x001fô\x0010¼ÿ\x0000¿ïþ4}]÷\x000fbû³Ey7ö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGÕßpö/¹ë4Wkj\x001fô\x0010¼ÿ\x0000¿ïþ5Ûx*âk&wi&ap@i\x001c±\x0003jñQ:.
÷&TÜUÎ(¬LÂÈñLÒAáë©!âJaó¨ê+Ïµµ\x000fú\x0008^ß÷ÿ\x0000\x001aÖ\x0014Õîi\x0018s+³Ey7ö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãZ}]÷+Ø¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ%y?ö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGöµÿ\x0000ý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^JÚ¶¡´ãP¼Î?ç»ÿ\x0000zÕeRäJ\x001c¡E\x0014Vd\x0005\x0015ÃxÎúêÛX º\x00146êvÇ+(Îæçô®û[Pÿ\x0000 çýÿ\x0000ñ­ãAÉ^æªjç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÕ}]÷\x001f±}ÏY¢¼û[Pÿ\x0000 çýÿ\x0000ñ£û[Pÿ\x0000 çýÿ\x0000ñ£êï¸{\x0017Üõ+É¿µµ\x000fú\x0008^ß÷ÿ\x0000\x001a?µµ\x000fú\x0008^ß÷ÿ\x0000\x001a>®û±}ÏY¢¼û[Pÿ\x0000 çýÿ\x0000ñ£û[Pÿ\x0000 çýÿ\x0000ñ£êï¸{\x0017Üõ+É¿µµ\x000fú\x0008^ß÷ÿ\x0000\x001a?µµ\x000fú\x0008^ß÷ÿ\x0000\x001a>®û±}ÏY¢¼û[Pÿ\x0000 çýÿ\x0000ñ£û[Pÿ\x0000 çýÿ\x0000ñ£êï¸{\x0017Üõ+ð=ÝÅÓ_ý¢âiöù\x0016Æwg\x0019ú
ë«	ÇØÊJÎÁE\x0014T(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000åh¢ùóÛ:ª(¢¾ñ\x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002¼ïÇír\x001fúö_ý	«Ñ+Í¾"¶5Ëúö\x001fú\x0013VÔ>3J_\x0011Îo£}VßFúî:Nÿ\x0000U·¶K­i\x0004vo\x0014\x0016À¥¼0\x00056!pù
2 ä\x0013yôªí é¶·âÞy<rÂ
Âf}ø
\x0003r`{ä~c:Õó_ËzÓæâUÙ!(¸uÆ0W\x0018#\x0000qtºî£4{^å%\x000b:¨Wr¿t³\x0001Ç¹53å}ÎM*Æ[Ë]fXäÕ>ÄÆê¡3Õ¾éÈô\x0018\x0018õ4EáÛo·i¶ÒM3}¦KäeÀÿ\x0000TH\x0004\x000c\x001cg\x001dó\òxPIdL¤LA\x0008\x0012\x000fã\x0000\x0006÷\x001c-¼C©Úìò¯\x001c\x0014fpX\x00069o½É\x0004àqÓ<õæY÷\x001d¥Ü¹«ÚÛXÁb"\x0013\x0019®-£¸fg\x001bFàr\x0000Ûê:æ²÷Ón¯ç»ò|ù7ù1,)À\x0018AÐqPo­RijZó,ï¯Cð\x0001Î9ÿ\x0000§ÿ\x0000ÐV¼Ï}zWÃ³\x0006cÿ\x0000O-ÿ\x0000 ­e_à3«ð]\x0014Q\'1ã\x001e<1yÿ\x0000\x0000ÿ\x0000ÐÖ¼¿}zøðµïÑ?ô5¯'ß]è¥±g}tZx|,×\x001b¬áí»<Û<Ì®ÀvýÖïÏJå7ÕË}^êÚÐÚÆÑ4\x0005üÍB
ØÆ~`{VÒM­
\x001a¹ÒZh¶w£N/<~ gÃD F
\x0013\x0003\x0000ã»×¨Æ\x000b#Ñm%Ô4%iÕï-ÒâI\x000b\x0000*Ä¨\x0018ÿ\x0000g®OÐÖ\x0014zíüR[<sª\x001bbæ\x001d±¨	¿ï`c\x001cçðíQÿ\x0000l^ý¦Öà\0Õ\x00168X\x00006¨è:sÔõëÞ£]É´»
hÖ2/·\x0007\x0011ÚÍ<Öé:JÊP
ê03zv?ÒèöPiJ·\x0012,Mok1HÕùA8Á#\x0000g\x0000ûdÖ
·.cZc¾%¢\x0011F\x00165
Ç'\x000b´¯=ò§?P\x0008Pñ-åÓb\x0017x#ò¢å·;yg*Åð\x000eíÄRå÷\x000bHèì´;\x0008õ?ÜÍqm,#ÍI!j\x0004\x00079\x0004\x0015#R\x0001\x0007'û6Íìô¦ÏYu)Z5,à¬@H\x0017´nàúk)üA©4±È.v<r¹à±
\x0000bG\x001cç©õ¨%ÕnåKtiv­»3Â\x0011Bl,w\x001c`\x000csùv¦£.à»\~\x001fÓ¥Ô¢µ\x0017.nd¢\x0017\x0011ÈåU	\x000fÀùy\\x0010GzÎðÚÛ]xÚ?#u»nýÜÄIü\x0007¯\x0000\x001e}«;þ\x0012=LN-Â££´dH »\x000c\x0016 \x000c\x0013ç5NÊþ{\x000b¤¹µË3µ°\x000e20x<t4rÊÎì,ìtèÖpéÉ$·>\Ïd.Úd\x0001ò#\x0011ýãÇ|õü©t«K;­\x0002\x000f´#\x0007RX\x0003Æ\x0000|\x0015\x001cn=\x0000Î{ô÷ÈÁþÚ¾û/Ùüÿ\x0000Ýù^Nv.ÿ\x0000/9Ù¿\x001b¶ûg\x001d¨³Ö¯¬`\x0010[O²!/´¢¿\x0018\x0004äsÐ~ \x001e¢Y[p³±»u¢Û[\x0008<ÉâîæK7 "ífvã'#¶êµmáë\x001b«µD{ã[Ùm\x001c\x0017V-µ\x000b\x0006\x0007hÇN?Zå%Õo&KuáÛììÏ\x0013tef;ÝÔóS¿5&9\x0005ÎÇS0òÑP\x0017<\x0016!@\x000cHãõ>´8Ï¸Z]ÍÛ
*\x0006Ñó{ùÙ\ÊÀª0\x0005\x0018\x0001©Ç^£B+jÿ\x0000F´»¹{T;pÚ¦ø£\x0000\x0016áÊLù×\x0010Þ Ô/(ÜþïÊxBì\\x0004|nQÇ\x0003L`bþ#Õ\x001eO0Ý°8O>p»sÀþï\x0018èi8M»ÜN26í´[\x001b(ï<Ë¡Òy¶e]£`:àd\x0010zqÓ­R¼ÒâMOM·GXïãA¿\x000ccÞq1~\x0015uÛò
ÕPÂÐlHÕT#\x001c°
\x0006\x0006OqÍA6¥u<ï$Í¾Ù\x00168p¥\x0015z`O^µIJû;;
\x0017KMb\x0018Ý¼Ç["û;Ü$©`ä(È\x0019R
QCÏéö_Ã©\x00142$°Bg\x0016\x0005v)ù\x001crpF0\x00075QüA©4±È.v<r¹à±
\x0000bG\x001cç©õ¥ÒµuÓ¯ÚøÁæÜÆ<0DRA\x0007*\x0007#d¬Ñ²-·ü$öÚCÉ7ú±ç°#ïì,v}ÞFzÓtí2ÆîËí²4@×K\x0006×¹Dò×nY2áºô\x0000\x001f­`CªÝÁ¨øåÛtYÉ´\x001e[9ã\x0018îiÖz½å{-åPÄ^5p®:0\x000c\x000e\x000f¸¦ã.ã³ît@´ób.$À[Í,®¤oc\x0011ÚÅ8#\x0004#'¦y©.<=c\x0005Ùµ{¢²¤°GÌÑ9\x0001°S\x0019Ï9ãó®_ûb÷ì3Ùh.\x001fÌX\x0002]²\x000eI#=z¼A©6Òn~`Èå(g)÷w\x001ce±þÖirÏ¸­.çQa¡Yµú\x0018ej^Ëhþb£nÛ\x0019`@ 1AÏ^:V\x001e¯kmc\x0005Lf¸¶ám\x001bÈ\x0003o¨ë§\x000f5(\x001c¼w;XÎ×\x0004ìSûÆ\x0005IéèO\x001d*­Õü÷~O&ÿ\x0000&%8\x0003\x0008:\x000e)¨Êú±¤ï©Ó>göYÄÿ\x0000Ùû\x0015\x0007¸õ9ý1ß<]Ö´kFÔK hDV"\x0001T+F¤1×&¹Ëß\x0011\Ü[Co	h"KT¶p\x0008;ÀêAÆW<d\x000e¸\x0019ÍGÿ\x0000	\x001e©ç¼ßko1Ýd'bðÊ0\x0008ã88ê89©å÷&Ò7SB²\¤2Os42Ì\x0014N¾dJ¤m
ý³:àsTtÈ­dðö±<°³Ï\x0008#îû»°Ç¨çÔqÇ5¾ Ôq\x0017?1gpÅ\x0014²\x0017ûÛN2¹ÿ\x0000g\x0015VÞþ{h§)1\x001cë²D \x0010Ã·\x0007¸ìzÕ\²êÊ³:¸¼=m$#{Í\x000cÉ$\x0002HÙÁ}²>ßvüG8Ëc½U}6Ä\x001d^M×)\x000eË\x00167+31r»º\x000e\x0000\x0019ÛßÔVWü$zÒ>Ð¹%\x000b?¡\x0005K62ØÀêj\x0008õØ¦¹;W¹;¥ \x000fç9Æ8 ò\x0008ävÅ%\x0019÷\x0015¤jø©"·ñ\x0015ÜPÆF»0 \x0001ò)è+\x001f}6öþ{û§¹ºÌñ¹°\x0006p08\x001ct\x0015\x0006ú¸«$IY\x0016KäW¶W«åÖ½Ò¹ñ\x001d\x000c«t
(¢¹L\x000f;ñûc\þ½ÿ\x0000Bjå÷×Gñ\x0015±®[ÿ\x0000×°ÿ\x0000Ð¹=õèRø\x0011×\x000f\x0016w×O K­;@F\x0008Íü¯\x001cÏ\x0014\x0011«\x0010$\x0000`ãJã÷Õ¥ÕnÕ,ÐKòÙ1x\x0006Ñò\x0012w\x001eÜò;ÕI_aµspiÖm¨ßÄ\x0012u¶³%dI¨Á#qm®\x0000
\x0014Iç¿?lmf),×/ôµ]»GÊè¬3ÇQ»¯|t\x0019Èå£Õï#æA*±º9^5esä©\x0018ëíÅK75)Ü<;N·\x0000ìQûÅ\x0001Aéè\x0007\x001d*\x001cgÜK¹»\x000ehñN4×w0É*K\x001c\x000c¡ã\x000bÀa\x0019ûàtaÔ\x0001NM\x0013O(¢In0_1]¤)ô\x0003¿ÓNxÀ_\x0010jK¸³¸bY\x000býí§\x0019\ÿ\x0000³göÕ÷ü÷ÿ\x0000o²}Åÿ\x0000UýÞ¯_z9gÜ-.çDt\x000ba\x0004Aäh¬\x0013¬M2FA#\x000cqØg#ñ´ºf\x0014\x0011Æo\x0011õ(íÄÉ(ù\\x000f\x0003v\x0008\x0018$äp\x0007*5Ûð\x0002ÕB°lxÕ¢¨*F\x000e\x000fsÍ6MoPÍó.²d8èÊöã\x001cqÒ,PåswU²±ÛP½\x0011Ì¬·ïm\x001ci"\.s½38ã÷£XÑ¬ôè.Ô\ââÛËÚ\x001ad&}ÀnÂ\x000fqó?:ÀºÕï.á)åVI¼öQ\x001a®_\x0018ÝÀôÿ\x0000\x001auÎµ}u\x0003C4ûöù"hÂî`2Ø÷&´Ô\x0012d[èßU·Ñ¾µ,ï¾\x001dGþÙìõÛ×\x000bðÔåu/¬û5wUÁ[ãg-O\x0014QY\x0010\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000r´RQ_<{gWE\x0014WÐ QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000Vn£¡iº¤ë5í°E]a{\x001fsZTSM­¶0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢<»÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ£þ\x0010ý\x0007þ|\x0007ýüñ­Ú(çpæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000Æ´´í:ÓK·0YEåDÍ¼®âyÀ\x001dÏ°«tPäÞìM·¸QE\x0015" ½³þÕí®£ó!\x001b$g\x0007=½Ådÿ\x0000Â\x001f ÿ\x0000Ïÿ\x0000¿þ5»ER[1¦ÖÆ\x0017ü!ú\x000füø\x000fûøÿ\x0000ãGü!ú\x000füø\x000fûøÿ\x0000ã[´QÏ.ãæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000ÆøCô\x001fùð\x001f÷ñÿ\x0000Æ·h£]Ã÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ£þ\x0010ý\x0007þ|\x0007ýüñ­Ú(çpæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000ÆøCô\x001fùð\x001f÷ñÿ\x0000Æ·h£]Ã÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ£þ\x0010ý\x0007þ|\x0007ýüñ­Ú(çpæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000ÆøCô\x001fùð\x001f÷ñÿ\x0000Æ·h£]Ã÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ¤ÿ\x0000CBÿ\x0000\x0001ÿ\x0000\x001fükzyw\x000egÜÃÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ£þ\x0010ý\x0007þ|\x0007ýüñ­Ú(çpæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000ÆøCô\x001fùð\x001f÷ñÿ\x0000Æ·h£]Ã÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000CBÿ\x0000\x0001ÿ\x0000_ükv)97¸op¢)\x0008ÍÔt-7Tf½¶\x0013H«°\x0012ì02Ocîj§ü!ú\x000füø\x000fûøÿ\x0000ã[´U)ÉlÇÌû_ðè?óà?ïãÿ\x0000\x001fðè?óà?ïãÿ\x0000nÑG<»÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ£þ\x0010ý\x0007þ|\x0007ýüñ­Ú(çpæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000ÆøCô\x001fùð\x001f÷ñÿ\x0000Æ·h£]Ã÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜ¡¦é\x0016:Wö\x0018\x0004>n7üÌsã©>¦¯ÑE&ÛÕÝÂ(¤\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0007)E\x0014WÏ\x001eáÕÑE\x0015ô'\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014´\x0000´QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000rRQ_:{ö½Ç÷"üøÑý¯qýÈ¿#þ5RA\x0017(MÁr	Éè03[ªõ[²£M+´\þ×¸þä_ÿ\x0000\x001a?µî?¹\x0017äÆªE\x0003Hd\x0007äòÔÜ\x000e^?CL1¸@å\x0018!à684ýµk^ì=-¬ßÚ÷\x001fÜò?ãGö½Ç÷"üøÕ4·äDØÀ¹ÀÈ?åM1·\x0003kn,W\x001b{ú}höÕ»°öT»"÷ö½Ç÷"üøÑý¯qýÈ¿#þ5KÊyM¸u\x0018çüò)\x0016)\x0019Ê*1aÔ\x0001È£ÛÖîÿ\x0000¯{*]{û^ãû~Gühþ×¸þä_ÿ\x0000\x001a£\x0012y"g\x001b.}3J±±¤Ãm^2\x0014¯ùíB¯Yý¦\x000e%Ð»ý¯qýÈ¿#þ4kÜr/Èÿ\x0000Qòß`m´óqéOH\x001d¤YY\x0004\x0000ÄuÏz\x0015jÏ«\x000feItE¿í{îEù\x001fñ£û^ãû~GüjG(\#\x0014\x001c\x0016Ç\x0002\x001b\x000eQ\x001e\x0003cKÛÖîÃØÒìßÚ÷\x001fÜò?ãGö½Ç÷"üøÖ}H±\x0016L]Ø'nyÀëíëB¯Uí ti®Ïí{îEù\x001fñ£û^ãû~Güjqï\x0005*(ÀËg©ú}
\x0002&2Î\x0003.sØëOÛVîÃÙRì]þ×¸þä_ÿ\x0000\x001aQ¬O`Æ©4,\x0018\x0005ùÁ\x0019\x0005Aç>)¾[áNÆÃð¼uúQíë.¬=.Èèm/#º_åqÕMY®d+Áp :«6ìð8ÍoÛN'\x001c©ldã¡÷çèkÐÃ×s÷e¹Å^±Ø(®£(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000äè¢ùÓÜ
\x0006\x0008ä±ÀØÃóR*:)§gpjêÅ¿=\x000eÞÄ£\x0017>­·hÏ¯¯ü\x0008ÒI*\x0018NÝ\x0015\x000f
»~\x001dª­\x0015~ÑìÑwí\x0008n]ÙÉ\x0006upN~èÏÿ\x0000Z£DDT,\x000e\x000c \x001cr \x0003U¨£Ú0öh²eT_$E³#8?>`
  
  
  
  
Instances: 1
  
### Solution
<p>Ensure that application Source Code is not available with alternative extensions, and ensure that source code is not present within other files or data deployed to the web server, or served by the web server. </p>
  
### Other information
<p><?=ÄÓ¡d.`ÍÂ\x000b_¼¤b#÷þP\x000ft±.MÇïZL\x001edÎê¤÷U$Ô\x0007BGJµ@\x001cö¥xñjÈ#g\x0012	áL4ì>Fe\x0004ÚSæ#{\x001f¼H\x0007«:\x0005Ö!\x001béep@n\x000c}\x0014ü¤òzN3Ðcb\x0000åí¯%?h)t²Ú\x00151Ü¼àîkaØ\x0002A\x0000\x0002\x0006G\x0007¾ióI:XùÍpì_Ln\x001a$HÕ¥Ú7\x001bóÔð¹Æ\x0000éh \x000cVuð¥Ü¦lÈ°LÉ$nÇ\x0000nÙ \x0016ÀÇÍß¯9ÍB.\x0002Ç}äÜ\Mn±ÄYÌ\x0015³\x0007\x000cÄ~ï\x0003i`\x0000Ø2@\x0006·';$UÝ\x001cªQ×8È#\x0004Sè\x0003´k¡\x000c\x001e|±Åöó\x00101NÏþÎ_\x001bØ\x0006`IÎ}ÆÓÀ4éd¾Kkæ>,¶[2¼\x0019\x0006æv\x0019Áò6ñÓ{\x001e¼\x000e\x0000ç i§Ò1tÂ\x0019/J©·¸i3\x001fÄ¯À\x0016ùç·@A^#¸º¸[)¶Ï(1Úß;Îw"ª\x001c÷ w<õõ®\x0000«"]>\=ÄÍ¹pò1äð\x000f\x0019ÏAvÆ8¬Ý\x0006å¥»»:´(º\x0015¸yÔ\\x0012\x001d'î\x0008=ó[P\x0006</p><p>,i¥MrC\x0012{Ã#ìÚ­pwdÿ\x0000</p><p>ð2Ý@\x0004­mvÒ[\x0015vÍo|·\9\x000b\x001f¸~ôá°\\x001eù\x0000\x0012\x0008ÏOE\x0000sZj}¥í"\x0017s4\x000föÇfM¾v'\\x0012W\x001e¹Êãò$\x00165ÅÊi+9º¥¹Ò¦¸tp©´¨\x001c.7\x001fº\x0006{äó]E\x0014\x00013J·W\x0002âlÅ}\x0004HÎÅV\x0011\x0006ùz\x001c=s£\x0007&¢vû"4×J©öÄ·/n§\x0012°_Þ(ì\x0001\x0001{á®\x0000åî\x001bý5Ý.. ¹\x000b/¾ûd\x0000ÌUOº\x000fL`\x0012¼s-õË[jqG\x000bË¹&!æ\>v\x0016PH\x00042½w\x00123µÑÑ@\x001c­´[Ãq\x001d²¼¨	¼È|ÅvðIç\x0004}w\x0013Üæy&\x0005.\x0013O½í·Ú'2ív\x000e\x00031?Ã·åéÏNyèè \x000cí:A\x0014×ví+\x0015àG\x0008Ë1ÌJäd¬{ñì*¬Ò¬ú©q2}Åf\x0011È]ù#¿Ý\x001c\x001e\x000fpp1µ$1Êñ;®Z&Þ=\x000e</p><p>çòcRP\x0006\x0005ëÜZ}¶\x0018f@©o#4²\x0011÷¤a!Ýü\x0003jÿ\x0000\x0008\x0001pH\x0002£¦;HÅÓ\x0008d½*¦Þá¤Ì~K\x0012¾c\x0000[æ\x0007Ý\x0001\x0005xèè \x000ezk\x001a~®ÿ\x0000j^$W\x0005£\x000cq\x0018\x0005¼³à;pF1¸\x0012yÆF¯ D¶óehmlO s\x001eÕØÄe\x0005~`£¨ôïÑ¢95¸d³µÿ\x0000HF´ynM%Ù·Wo;å;ÐrH,p0\x000f'µk_\x0019OîMÃoØ·ÛJå¼³\x0001\x001cöÀ­j(\x0003¸ãûqãó\x001cO\x0018ZáÃ4xBØ\x0002\x001crãqéÏ#o\x0016õÉ\x0004~A{?+%ÃÛ«\x001e0|Å\x001dG?/|ü5­E\x0000s\x001aÕôÚ$¨×	2Úc\x0013JbmØ';\x0011pì0\x000b)ù@Ç@MY¼ÇÛ÷Üùq¥â©\x000f+D»|;|ÁÌcqÎ{?·¨ \x000ejêêQ§ïYgÝ²!<©@¬\x001bÃû¬y ÔÔÔ\x0003ÚéxY¥ :	%fù¶\x0017\x001ec\x0013ü?)c£¦1Æ\x0014\x0001Ì$ð¥µóEtÓ[µèQ7Úv&<ûò¨$\x0001drN\x0001''2X<×íc\x001có\F.·"HÊHIUT\x0013Ãp;ðÞ½H=\x001d\x0014\x0001ÌIy#Zi÷\x0013Ü±KXä\x0008³\x0018\¹\x0019%\x0014
²±ãä<\x000c\x000eÍ[\x001aü~iõòßú&J¿E\x0000sÞ\x001fâiÐË2\x00170fá\x0005ÃÊÂL¯ÞR1\x0011ûÿ\x0000(?ËÅÛ@Ö&XHÍº£\x0011æ1fÞ6ÿ\x0000\x0017\x0001sv:Ö¥\x0014\x0001Ï%ãÿ\x0000oÃ\x001a3þòy#<ìÌ\x0014#\x000cxÚí\x0005NrÀgµP7\x0019¥KÇ{ÅÒ®\x001etórÐËÉãª\x001cÿ\x0000\x000f\x0000mà\x000ek°¢9­U®-®	s 
\x0004\º\x0016³äU>iû&08\x0000`âµ5y\x0002%·+ClÓby\x0003ö®Æ#,\x0008+ó\x0005\x001dG§|V\x0014\x0001]}¾U¶ÿ\x0000HÅ´
1u2å</p><p>pÇ\x0003#\x0003ôÅkQE\x0000\x0014QE\x0000sRQ^!ë%\x0014Q^Ùä\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x001c¬6³yam ¸øiÓG3ìd\x0006såó¸áK\x0012\x000fÌ\x000f8\x001cð*{kOô;ÝË\x000b\x0008ÿ\x0000w
B\x000cK~í/ØÆå\x0018\x0019<\x000e\x0000ç¾Î\x001bIÚmöD³ä*Ú9ÆÞ¦\x0002w\x0005Éè?\x0007èM8Â+\x0013{dÏf©(1\x0008\x001aE\x000cYv7Wå
~è;x­ú(\x0003¹æ
2á.b¸âãK\x0001±\x001aRÒp%AÇ,9=sõ«w0ã[Y\x0004
,Ðð6å^\x0001)08E\x001cw\x000e+r\x0000j8u$\x0006\x0003$|ÊGCÿ\x0000äÓ¨¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>JZJ\x0000Z(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢9º(¢¼3×:J(¢½ÃÈ</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>dR'aÔ\x0002iõ\x001cÿ\x0000ê$ÿ\x0000tÿ\x0000*\x00001/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4b_ï§ýðÆ¤¢#Ä¿ßOûàÿ\x0000\x0018ûéÿ\x0000|\x001fñ©( \x0008ñ/÷Óþø?ãF%þúß\x0007üjJ(\x0002<Kýôÿ\x0000¾\x000føÑ¾÷Áÿ\x0000\x001a\x0000\x0012ÿ\x0000}?ïþ4±±xR\x0001§Ôp¨ýÑü¨\x0002J(¢9ª(¢¼3Ø:Z(¢½ÃÇ</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>õ\x0012ºIQÏþ¢O÷Oò 	(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000*8?ÔGþèþU%G\x0007úÿ\x0000Ý\x001fÊ$¢(\x0003¢+Â=¥¢+Ý<p¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¨çÿ\x0000Q'û§ùT\x001cÿ\x0000ê$ÿ\x0000tÿ\x0000*\x0000( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002£ýDîåRTp¨ýÑü¨\x0002J(¢9ª)(¯\x0008ö\x000e(¯tñÂ( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002£ýDîåRTsÿ\x0000¨ýÓü¨\x0002J(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>\x000fõ\x0011ÿ\x0000º?IQÁþ¢?÷Gò 	(¢\x0000æh¢ðdé¨¢÷O\x0018(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000*9ÿ\x0000ÔIþéþU%G?ú?Ý?Ê$¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¨àÿ\x0000Q\x001fû£ùT\x001c\x001fê#ÿ\x0000t*\x0000( \x000eb(¯\x0004öN(¯xñ( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002£ýDîåRTsÿ\x0000¨ýÓü¨\x0002J(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>\x000fõ\x0011ÿ\x0000º?IQÁþ¢?÷Gò 	(¢\x0000æ(¢ðOdéè¢÷\x0018(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000*9ÿ\x0000ÔIþéþU%2E/\x0013¨êA\x0014\x0000ú*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ$¢£Ì¿ÜOûìÿ\x0000\x0019ûÿ\x0000}ð 	(¨ó/÷\x0013þû?áFeþâßgü(\x0002J*<ËýÄÿ\x0000¾ÏøQ¸÷Ùÿ\x0000</p><p>\x00002ÿ\x0000q?ï³þ\x0014f_î'ýöÂ\x001b$ÛfXwÈpHÎ\x0002¯©ýp;`Ht\x001fê#ÿ\x0000t*®¶¤lÊÃomÏ÷ß3qÉ\x0018ã°ã\x0006,Æ¥"E=@\x0002\x001fE\x0014P\x0007/E\x0014W{'QE\x0014W¼xÁE\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E`éæDÉ¥k¥^\x001ec7
ÉØIØ7 ãp;G\x000b3ÓÒ¥iô)\x0004cÉ<\x0007©$Äæ-ÑYÚ\x0017	g{zÉ\x0013[À&Û\x0018$6cb9<»i=\x0006:sÖ¦]Ïq$É2³\x0004</p><p>V_³I\x0000lç+µòN0\x000esüCÓ
\x001a*ÍÅÂêv¶Ð¶H$ùÈ</p><p>È8Ç®â?^Ø96z³ù77æÙ=©¹'É=@+\x001eöÈläà®\x0007\x0004ãæ \x000eÎ¹îÖÐy²[ùÅö«¬NÛ3Ä`'0\x000f@[<b«A©^^\x001bXíÄ(Ò¬ûÞXÛ\x001bªd&Aç'å$\x0011§\x0018 \x001bTW9qsw\x000crÛ2Û\x0012Ê^w6<ÉH#\x0007¦}FAí\x0008µ	_ì¹TýõäÐ7\x0007O7\x0004s×ä\x001f­\x0000iÑ\àÕ§´Ñlæó\x0016BI4bWåÏ$pÁù9çæUðjSÆgF\x000f|c*Ø}°ãw#§\x001d3Ô\x0000oQYÚ\x0017Ú=´ÓHÒÍp3±'«\x0000x\x0004}\x0006\x0007 \x001d*¦«]ÝÇæ%³J$·3ÆKÄ\x0015¸Ä{Ûålçï\x000c\x000fsÀ\x0006å\x0015qyy5\x0011ÜÄ²­Ä\x0003q·&ÃH\x0006</p><p>1\x0007\x001eùÁ\x001b\x00063Z÷×\x001fc°¹¹Ù¿É¤Ûg\x0000gð \x000b\x0014VtÓ^Âð³[æ1¬¡\x001bh\x001b\x0019òS9þ\x00121»ß=ª\x0004¿½¸Þ\x0008~Îâq$¬@1H© ÷Éã<g©Ç \x001b\x0014W8/îg¸K½Ê±µ½³Ã\x000fÍi¦[\x0004\x0007Ç\\x0011é§$ÛkûÐél¿gkµ}¤*ÁHòLä8\x0018Ï8ê3À\x0006Å\x0015ºû²m[P³\Ëm\x0018!²»KüçxB6÷<î\x0019Àl´ûmã]©+:ÛÉ0>S8E9\x0019Îy<tç9 
Ê*\x001bI^{Hf&äEfº¡#$\x001f¥e­é\x001aä`o5Ü\x0018â\x0000\x00143s'Ýr6·\x0019RÌ3ÁÈ\x0006Õ\x0015Vöáí	\x0000S\x0019#=pÇhÇü\x0008®}³Þ²ÿ\x0000µîÖKÄ+\x001c6Âð«)&HØ¹UÎ~VÚ'æ\x0019=8ä\x0003zÌöâ=HDÁ#rªïÈ\x001csæ\x000fNI\x0001HÉ tÜ1~y<¨$(6)lÈÛWÜö\x001eô\x0001%\x0015ÎO¨ÞO\x000cÇ2¤±Íl|Ók$Y\x000f.Ý»\x0019³Û\x0010Hã­\x0010j7C\x001c2L¯,\4ZÉ.\x0002K·nÅl÷àç\x0000\x00009ë@\x001d\x001d\x00156«z#e(\x000b(îä@Åòw\x001fl}Þ§§¡Ï\x000c{û»[ÕiUÄ¢\x0018äò\x001fî©Ëp1Ioj\x0000ß¢±ÛP¼6pH"hK\x000f#ZÉ'Ýl/îÆ\x0018n\x0019nzc\x00079\x0006µ Í92zÌm¹y\x001dqï@\x0012QYw\x00172AzD\x0002[ÀT>JÏ ÈQÉ=8\x001c±\x0000f¥Ò¯^ò9Ä/\x000c¾Yo)¢Ýò«gcr¿{\x001cúg½\x0000_¢²u
BêÞ{¿)a0Ú[-Ëï\x0004³òùQÎ\x0006BuíèsÁ6¡tÞíXDpÏ\x001d¼dIgòù<ô\x001bÉÇ~c$\x0003ZÉûuÖï²æ\x001f´ý§ìþnÃ³ýW³ÓåÆïj¯ªßÌ¬Fß|D&$IKaA\\x0005Á^\x000b\x0003É\x0007\x0003m\x0000oQX·÷wM$"\x000c7Büç-\x001b\x0012\x000fLaöíÇ©Ïj-BWû.U?}y4
ÁáSÍÁ\x001cõù\x0007ë@\x001atV\x0002j×i`ÒyQËw	1ÛÉ8P\x0002qµNyÝô\x001d9ë[6¼öÍ$M\x000bÈÍ\x001buBFH?J\x0000Åû]Ô×ÖO[g¼-ªHoe^{0%sÛ\x0018\x001dzi\x001a¤÷òF^6ò¦Î\x0007ìòF"û¸]ÍÃçqäcî9à\x0003b©¨Ï<\x0010+@¹%°Ïå´\x0006\x000f;\x0017ç\x0003\x0003¦sÐ\x001a©.¡0µ·d\x0011$²V	%'iÇ\x0011®\x0018{äü§åç9 
j+\x0016-JyÑç\x001fìíæ\x000b}»Ëäà}í g\x0000\x0002ØÇ¦$öY\x001aÈ;#³\´lU^#)Û'*x\x001c\x001c`÷\x0018\x0000Ö¤¬#TþHËÆÞTÐùÀýHÄ_w\x000b¹¸|î<}ÓÇ<[»¸¸[¸-í[Ý\x001eRdÎ\x0008R£o\x001d3¿ïst4\x0001vÀ´Ôî#Ñ^C¶GKä3är¯Ç<ýÁùÝ9lªø;K\x000c{ddgó \x0007Q\Õýä:YÌI\x001e;4¾È\x0019»Ã\x001d«óa8NÀ\x0014t«·:ìr^\x0018Ü¤\x0017\x0011@\x0002åü¼äöÆóÎ\x000fQÇ\x001f0\x0006Å\x0015/ïcA/ÙÙ-î#·rªÀÈ_f\x0008\x0019;vï\x001dÛ8?v¥PþËOß^M\x0003pxTópG=~AúÐ\x0006\x0015Î
Z{M\x0016Îo1d)dH¦)%y>\òG	\x001f³xùNmË{r·Cn"Ü÷¢\x000cÈX>Î\x001f8Ïb:\x000c\x0003ìI4\x0001±EcÚêÏ¨\x0008Äla3I	\x0002ÞAåìÜ7\x0019>ëd®0\x0000Æî¼sgYÝö\x0010ªîç	G*pePFG#h\x0002ý\x0015©ÓàºÞi¶=ó\x0002ò³²:\x0005\x0000«\x0012HûÞ½1Îf73-í¤Ò7\x0007y\x001c	#1Ë°qü<>e8\x0018Å\x0000lQX:y&²iZédÍæCrv\x0012v
çh8Ü\x000eÑÂãâ´õ;¦²±irÛ\x0007Ê[\x0005.p98Îp98Å\x0000[¢±×P¼k'q\x0013nY¼³1µ|»AÞ"ûç·\x0000ûô\x0018¢\x000bõ[\x0016óâ0µ¼ÅÑ\x0011â®8'å<\x0008%~a
*£qq\x000bZGl"ßq13\x001b\x0019³Ç\méß¦Fr+Zê\x0017O-¿°ùrÏ%¶\x0010\x001cMù~O\x0000ùdmç\x0019\x0007qé@\x001aÔW=6±1ñII?Ðå\x001a8äWh\x001c\x0007$yîûËî1nMBé.®\x000eØ~Í\x0005ÌPc\x0007{ï\x0011óà`¾{ç§\x001dH\x0006µ\x0015ÎA¨ÞA\x000cpÉ2¼²Mr|Ñk$¸	.Ý»\x0015³ß\x0000\x0000ç­O6«z#e(\x000b(îä@Åòw\x001fl}Þ§§¡Ï\x0000\x001bVMæ§-½ú (Ñù±ÄQav9r\x0006LåB7gi\x0004\x0007?0Ãb¿½DÝöuI®&¶</p><p>Äf\x001cò?¹£ëÒ6(¬í\x001d®%Ð,ÝåV¸{uo1JðHÎOlóÏµdÛj×éöó\L¶QÎÛmä¦Ý»\x000b'aù~ñÎIÎ\x00061@\x001d=\x0015s¨^Ç%á-ÊAq\x0014\x0008\x0018°._ËÎOlo<àõ\x001cqó\x0002þö9$\x0012ýÞâ;w*¬\x000cö`·nñÝ³÷h\x0003bÅòòY¢··òPÈ×EPÏ´G0Qs\x0000và`ÖºÕâ;wKfb¶ñ^\x0008D2Kæ3nÂex\\x0015à°#$\x001c|´\x0001ÑÑXòêNH""!d[y\x001bvà¤·>UÀ|àáëÏ\x001b\x0014\x0000QX³Í*}§O\x0012¿,ê±6ã¿Ë,Ì\x001b *\x0016m¾\x0017Æfþáîafò¾Ï=Ä¶êNå)¿æ-\x001cùg\x000f½×@5(¬5+`±u$âÅ®|°vîp#Âz\x0003¼õö©ôÛ©n<ÕDvL\x001e xX\x0003¨ù8ãÎ\x000f#· \x0017èª\x0017Ý\x000bû{[S</p><p>ù±Hìò©m»J\x0001\x0008ÏÞéë0i>¯q%¡º""²KÉ\x0011Ábá\x001d6ãaç\x0007¯N9\x0000Ü¢³%Ô%OµaS÷7À¹\x0007+$ó×ç?¥TmjuæDªá\x0019Òù@ \x001c²²\x001cu#o©À\x0006õ\x0015×úÙ;ÂbYÌq¬¶²'Ú[h+µK\x0002½Á'#å'
mF\x001cF¢FV|
ÅF\x0001=ð2qùÐ\x0003¨¢\x0000åè¢ð\x000fhê(¢÷Ï\x0014(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢"]@eÆWÜg#ó </p><p>ÐiÖÐJ²F¯ûÒ³"vùT/\x001cp\x0006\x0001ÇJ\x0008c·8"]±Ä¡\x0011s\x00000\x0005sÚLóÃa\x000eëÍÖÚd3ñ\x0006Á!úã\x0004¨</p><p>8\x001c£¹pÔ/GÚíÖYVhØ\x0006¹XÉ&Ò\x0008ã\x0018Ç\x001c\x001eO=(\x0003dXZ%%I\x0015`Ù+÷SÀÉäã©äæmi
®ã\x0010rÍ´4@è2ÄrxéÉõ¬×ì$öé;Èñ\,Lëå\x0007ùr\x0002\x0016Éôû ÷ææê{8#¼xÕâÊÞRïÜê\x0018\x0012A \x0010yÀä\x0010\x0001¬a§IÊþñ\x0015[=\x0001 ÿ\x0000Ê M´xX·+©M®ÅÕTõU\x0004«ÓÀô\x0015ºäV	w$#Ï§Év#Ù!\x0000wÇÏÎIéÆ:TwFòX\x001e	¥º$ö¬­)Ë\x0007ÈÚ0\x0008ÈÎAê8 
¯ìëo#ÉÚøÝ¿Þfìc;ó»8ã9éÇN*»h¶e¾Äò¢e\x0008¥K²±*À½\x0008ÀìÄtâ¨éiK-ÖíÌm-ÜnE%¶Î\x0000\x00001ÿ\x0000¼q1.{{s%»Ü	Dw\x0016þwïL@\x0003òãË</p><p>wmùÞÉû¼ç¨\x0006ºm¤¨ÈbÚ¬±¦#b\x0008K \x0018#\x0018'µ\x0003N¶\x0017Kr\x0015ÄÅÔy­°1\x0004\x0012\x0013;rryÇrk3^yåT9¼¸à±ó</p><p>í\x0004I¸H\x0008=ú'\x0018#ÎzS¥àßÉ\x000c\x0012¬>eøF¤íû0cøäpNz\x000e b.Ë£ØM\x0002A$\x0019"\x0010ÞÀ\x0014\x0003\x0000\x001e~lu\x0019Î\x000f#\x0006¥\x0016\x0016âèÜlo4¸;Û\x001b\x0014Î3ºqùz</p><p>Í´½½PBÂQ\x0003ÜK	Þb\x0011á7³å¾Aä}î1A+Ïy¢ÛK%ó	&{IÊ"¦è÷È¼\x000e\x000fË\x0019Ê8 
ø!Þ\x0008àvÇ\x0012EÎp\x0000À\x0015\x0004Zm¤[ÂÅ¹]Jmv.ª§ª¨$^\x000c\x000e\x0007 ¬ëKÛÙu\x0004,%\x0010=Ä°æ!\x001e\x0013x\x001b9Þ[ä\x0019ÎGÞã\x0018Ã,%Ô.cÓÖKö\x0006òÔÎì± )·f\x0002qüç=8\x000bØ\x0003Kû.ÔÀñ2ÊÂB¥¦rÿ\x0000)Êüäî\x0018<\x001f_SVäD6EWF\x0005YXd\x0010z+U¿\x0008æ\2ØÅt|¿-cÜÁ\x000e\ä'Ëü'8Ï=*Ü·7iuu ¸ýÔ7À°ì\x0018!ÄA²zÿ\x0000\x0019#\x0018ç®G\x0000\x0002ÿ\x0000öu·äí|nß¿Ío3v1ùÝqôã§\x0014ø¬à¢hãÃD¬rIÃ\x0010[>¤	'ýMTÐchìd\x000f+Ê~Ó?.\x0017?ëXv\x0003Ó?R{`UE¾¹\x001a*\ùþl÷\x000b\x0003ùjª\x001e?5;sNÝÝÁÉ=4×M´X¼µ	å$Cæ9</p><p>)	$\x001e¹ïÅ,V\x0016ñ\x0008ö£\x0013\x001b\x00033³1b¥rI9?)Ç9ã\x001e±íw3Y$×\x0017\x00104w¬OdÁ-´\x0015\x0007\x0007N\x0008ã85ZÚîú
.Ö;s34ø§\x0004\x00182Á¸¶>A´\x000f\x0007\x0019ÉÎ
\x0000tg\x0002ù{cÇ+L¼\x001d·n?øû~tÇÓ­\x0002ítÃ;VF\x0005æù\x0007\x0004ó\x000fAF§4Zn¶»Ë\x001c[±¡ÝT2\x0001ã<gÖ±dkÝ±/p×\x0017ÞKDÞËöunòg</p><p>\x0001Ï\x0007\x0001Æ\x0000:\x0018<¯"?³ìòv/ËÆÝ¸ã\x0018ã\x0018¨\x0006h.äEûÔbêw\x001c)  g\x000399ÇSÉæ³òêE·In\x0016ØG¶7ú·U\x0001ðvô9m¤r8+CÊñÍ¨,O*É-ê¢UK·î\x0010áw|£NO`GR(\x0003bxc¸H%]ÑÊ¥\x001ds0ECsaou yÆÓe\x000e=\x0018\x0003\x001c\x000eG'ÔÖ^}s~ú~ÙöÆë;9Ú¬d\x0011Êª¼\x0001 òG\x001cc(Þ_Mqe{\x0001fI´ùnC²Ä\x0001Q\x0014Q\x0008À¿Î1h\x0003¢{\x000bw¹\x0013²6ü ;\x0005b:\x0012¹ÚHÀÁ#<\x000fAV$D6EWF\x0005YXd\x0010z+\x0014K:ÜËj²/D&eDßl\x001f=0I+Ô\x0003\x001c`âòê{kqvÑ\x0002.D¨¥ËQO#\x0000úñO\x0003\x0000]þÈ²Ù*ùovos+ïbrÙÎAïô\x001d\x0000¡të)Q{ñæ»nw\x00041?8\x0004\x001c¸r£¢\x000bÖ}\x0006;éY"f¶\x0013;m,¨väg$\x000fLæ«h×\x00125õõ´]Ñäc7æn`Ã/¸Ï?(\x0002óXZ´rÆaPÂ e\åá@\x001d>ñéëI&m#Ìì®\x001eV\x000eÌ²²Àm\x0005p~S	\x0018ÈàÖsÊñÍ¨,O*É-ê¢UK·î\x0010áw|£NO`GR*îv×Úds¹ÜK:ÊB¹PNÞ2@\x0019Ç\x0019éÅ\x0000Húu³E\x001c{]\x0004yÚÑÊÈüòrÀry9<O4ømüÙöÃå$i\x0008\x0018TÚ[Û@ÿ\x0000çgáí\x0012òYVS6q0FpÉ_B½0\x0008'®IÏ\x0017®®ï#mFDb¸Þ(\x0017pÞ"É\x0004ðOÎq2Nr1
Ilà¥i#ËJªrAÂW\x001e\x0012H#ý\x0005\x0016pY«­¼{\x0004½ù$³`\x000c{\x000cç¦²â¹½uÚI%¤º0ùå\x0019|£';räc§ÝÇ\x0019æ j2Î.V`écÑ\x0014ÆwLFW}Häãw^\x0006\x00005&Òà¸¿{ÆýÑ${y\x001c\x0002ÄAåNá<\x001c\x000cæ§{8\x001dgV"v\x000eü\x0000\x0000AìFÕÁ\x001d\x0008ÏZÏêá®måi{©­Ì%Wjó0G\x001b³û±9<tÃt·þÏ77\x001eq»³3·È\x0014!\x001e^1]ç9Ï#\x000e(\x0002ÿ\x0000öu·äí|nß¿Ío3v1ùÝqôã§\x0014K¦ÚK°4[U\x0014&ÔbÊ:+\x0000@eëÁÈäúÌ×y`Õ!o.8,|Â»A\x0012n\x0012\x0002\x000f~Æ\x0008äóé¯o´æ\x0011|n"¬B"\x0018!;²wîùÎ6ñ÷x<ä\x0003Fm:ÚyÄÎ¯¼2¹\x000b+*³)\x0004\x0012 àÉ\x001d¥\x0003N¶\x0017Kr\x0015ÄÅÔy­°1\x0004\x0012\x0013;rryÇrj¤\x00177\x001fÚ@M3ùrJñ¦\x00024-Ä*ó\x0001yÝÆC\x000fJS{$1Û´ 0feÇæc\x0004	>]¼÷É_z\x0000´ëf\x0008Bº$</p><p>\x00123\x001c¬«1¸\x0010qÀã<àzUÑ#cU\x0011@UU\x0018\x0000\x000e</p><p>À»Ô®ßç´g#³ä<b4ËnåüÃ(èr\x00019=*ynnã»»Ü¢ÚÜ¤m\x0016À\x0006ÆDÜÌÝ@Rû¾ç6_\x001au°º[®$V.£Ím ÛÎ;Kmaok!xQÆÑf\x0008=\x0014\x0013\x001c\x000e\x0006\x0007\x0003ÐVB]Ý¯ò\x001f.i¢µë\x0018\x000f\x0010g\x001bzrT\x001c\x000cñrEOwst²ZÛA4ÓYYä¶\x0011\x0007%\x0019W\x0007ËüD\x001csÀ\x0003"5.m¢º$¡°\x000eå*ÅYO¨`A\x001c\x00128ìHïQ>hñG\x001bE8ùX\x001eX1ÎX\x0013É\x0007 ¹¬É¯®Ì\x0010\<¾Z-²M)¶òÝPK\x0017\x0004ä§\x001cl98nzU½z6NTY^ óÂ°)Ü­"©\x0007 `ôïß# X]6ÑbòÖ,'\x000fä*d¦\x000er\x0008$zç¿\x0014±X[Ä#ÚLnd\x000cÎÌÅÉ$äü§\x001cçz</p><p>Êç[H¡´
\x001a	®\x0007h±,YH\x0018\x000fòí\x0003¯|õ5f+É..£+x</p><p>Á\x0004¡¼¼,ÆFaÈ<º6r	çwJ\x0000¹maok!xQÆÑf\x0008=\x0014\x0013\x001c\x000e\x0006\x0007\x0003ÐS®m!ºØe\x000e\x0019sF=FT\x0007\x001d8\x001eº£Y·K+Åq4
Ë\x001aÇ
£;ò</p><p>Iã¯ªÓ?´.c1¸TgÓåÙm.¾YÉÀÎ9lØñÎ(\x0003B]"ÊX\x0012\x0006Ö4Cµ%tÜ`+`Ã¯\õ>¦¯ÕM6i.-Úi\x001bæi\lÇú°¬WoÔcHÎpq¥ª]\E%ëC3F,­EÀPªDïá²	ÇÈ:`òyé\x000bgJ³1Å\x001fÁ"A\x0010Q#\x0000È:+\x0000~a×ÏSêjV³¼ÍÑçÌfnO.»vüq*£5äëöÍ²cË¾\x0015àpån\x001føû~u­@\x0015ÚÎ\x0006ó7G2U¹<ºíÚñÅü©N¶\x0017Kr\x0015ÄÅÔy­°1\x0004\x0012\x0013;rryÇrk\x0016\x000f2ßJÒe¶ó·pA\x0003y[7\x0005XÝÁ]ÿ\x0000.s×=ºsVaúæ[8\x001aá­Ë¥Á¨ìUy\x0019PØ<ã#08À\x0005Ùt{	 H$1$B\x0010Ø\x0002`\x0003ÏÍ£9Áä`Ôÿ\x0000cÎó|¿Þy¾vr~þÍÿ\x0000¾x¬eÔï\x001eÖ[Á"*Å¦Gwå\x0004á¤eõë·å\x001cuàr9ËÅÝôQÏ\x001ce; Tk\x0011|É61Âq9\x0019\x001dsÔ\x000cP\x0006¢X[¥ÉQ·ä°\x0005ØªÔÎÐNNH\x0019äúêÚ+¸\x000c3\x0006(HoA\x0004\x0010A\x0004r\x0005cÛÜÌ÷±Å%Â\µ\x0006>ÅÈ\x0002ÜqÑ³r8\x001cUk¹îeÑïÒââPÒÙI*àFÑ¸\x0000dÄËÎÎ@ùþb\x0018`
\x0000n.l°O	WtJHdpF7\x0012N9<gZ[hf\x0019¤ZX	1¿uÈÁüÁþ^=Íì\x000b~Âáå\x0010Ï
´j\x0011\x0003â,¶x\x001b¾c\x0012s\x0004¹¿"\x00033Âíxa- ¤Ùäùü¡³ÓÛnAç \x001apiÖÐJ²F¯ûÒ³"vùT/\x001cp\x0006\x0001ÇJxc¸£w#{àÔ\x0010G È#j¯q<)m\x001d¸´óygÉÙ¼
ß.ÿ\x0000øG^Ùï©\x000c÷×2ÙÀ×
n].\x000cDlçd«ÈÊÁç\x0019\x001cÆ\x00004³­¼'kãvýþky±ïÎìãç§\x001d8¥K\x000bxäÑ\x0019Z\x0000Á\x0008vþ,nÏ?6H\x0007óÏZÏ¾Kß\x0006ÍpíåÉ5¶\x000e2S$s\x000fO\~u\x001dÝôÖ·±*Ï4ª³ÅlÙX\x000b6ÜèÅðÛ¾P\x0007N84\x0001µ$1Êñ;®Z&Þ=\x000e</p><p>çòcQ­\x000båí\x001e\­2òxvÝ¸ÿ\x0000ãíùÖ\7\x0017$EîÛmÅÔöÁU\x0014yj¾a\x000c8åÀ9ã\x001dæc4^
á\x001bÌ\x001b\x0011*ï\x001cd&@ã\x001c\x000e¸üè\x0002ØÑì\x0007ûõ4'çn#le\x0007</\x001c\x0001Àç\x0018É©ÚÎ\x0006ó7G2U¹<ºíÚñÅü«%îîmîîmÅï"k@	UÜ¾d¤0l\x000cd®;\x000e1ßë»ë¡4ÐÄeb×¢\x0005òBoUò\x0004.ï®zö'Ú/.Ô©\x0001eR]¤Ü:°,rØ ä\x0002yÀã<âÖ\x0016­\x001c±T$°\x0019W yc8P\x0007O¼zzÒiÍ5µÇúÀÎ§%IÀb\x0006v7`\x000cãç§JÀ³½¸¶Ð!h®PÚ\¦\x0015q\x0013F¨\x0000\x001e¿xç9ävé@\x001bói¶Î&-Î\x0019\|Ä
ÊF\x001b\x0019Æî\x0000Ï\qÓzÙÀ¾^ØñåÊÓ/'mÛþ>ßeÞÜ^[­çú[n²µ\x0017?*(YX\x000eÖ\x0004\x0012\x0014l\x0000`rIæ¦òuûfÙ1åßA</p><p>ð8Fò·\x000fü}¿:\x0000Ðµ¶ÒÚ;x\x0003,Qª\x0019`zdj²é\x0016K\x0014Q\x0008ßËv\x0005ó_\x000c½¹ùdðÙ\x0000\x0012;Ö%ë´¹$(?eÔÊ tGoòkJ{«¹¸feH.¡·\x0010]¬\x001fËÉ<nÏï\x000e0@àq× \x001a
g\x0003y£Ï*ÌÜ]ví?øâþT5
æn>d«3ryuÛ´ÿ\x0000ãùVm­Íß\x0003Ëqæ$×Ûö\x0000\x0015TÈAÏRß \x0019Î1Û<ÕMîDÇnÒÁ\x0003\x001fq\x0010$ùvòsß%}è\x0002ÌVpE"É\x001cxuó0r7æ@5\x0011Ò¬ÌqGå0HD\x0014HÀ2\x000eÀ\x001fuá³ÔúO¸ûEü\x001d$G³·:Ç·vã'<ó8\x0004ñùÕK½BòÜÝ¢òÖ5ÁvN\x001d\x0002å\x0014Ã.FsÏÞ§\x0000\x001aan÷"vFßÄ\x0007`¬GBW;I\x0018\x0018$gè*Â E \x0016#$üÌOSÿ\x0000äV<×\x00176KoökZ°E]Øb¼\x00001ôÏ't÷7L÷qÅ#enj#Ø$Ûä«a7|¤äsÛw  
C\x000cm:NW÷¬Ùè	\x0004üt~U</p><p>X[¥ÉQ·ä°\x0005ØªÔÎÐNNH\x0019äú4ùLÖhÌìì\x000b#\x0016P­b\x00088ã \x00128$dqX©Ý´°É4Å­Ú\x0006Hÿ\x0000xªÊ@W,ªà°ùòG\x001dÁ 
ô«8äf\x00111\x0005\x001a-#2\x00048Ê'h\x001c\x000e\x0000íRÛZCk¸Ä\x001c³c-$#\x0010:\x000c±'\x001c:r}k"KëÙ¦a7\x0006;4öq\x0016àQ\x0014ÿ\x0000)VÉlõù8\x001cËo%ÝÕÅ-ã«\x0018£æ$\x0011J\x00058$åîx\x0007òä\x0002íÞ\x0015åÜ\x0013Ê[\x0010£ª%X\x0016+È`A\x001c)\x001cu\x0004Ó¥Óm%Ø\x001a-ª\x0013j1Ee\x001d\x0015 2õàär}MVÕn.VîÚÚÜ\bDF6þ^ÿ\x0000 \x001fë>\|Çß§½Rúý ãÏHü>;£\x001cj¬­!\x0012\x00127sò\x001d½¹é9È\x0006´Úu´ó_xer\x0016VUfR\x0008%AÁ#\x0003;\x000fJ{ÙÀë:´y\x0013°wää°\x0000\x0002\x000fb6®\x0008èFzÕhgMJà5Â¤qL XH\x0018Ý«ä\x001e»¹=ñÓ<ÖiÔ/#Ó\x0005ÏÚ\x0019ãNì\x0002«U\x0008\x000bÓç?{=\x0007=r\x0001¨úE£¬`\x0017\x0012\x0006,F2X6IÇ\x0019'ÇJ»\x001a\x0008ãTRÄ(\x0000nbÇñ'øÖ\x0016¡u¨[Í,Q<²µ½¸º\x00082Ì_Þr\x0010m\x001ftç\x0019É'\x0006·è\x0000¢(\x0003¢ð\x000fhêh¢÷Ï\x0014(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000¯\x00046¶¬±A\x00140±^\x0011\x0014)*\x000ez\x000eÀ·æÞôGek\x0012\x0004Ú\x0014A*Æ\x0000à\x001f$sæá¸ìÞéæÔF;É\x0016ï1£÷yùy*wq·§\x001c\x0001ÍY¶ÚÎõ£»[¨
\x001dÔ</p><p>\x000eã¿2Êåp\x000e3°|Üw\x0000ÝÖÞhäX"%!Y\x0001\x000eF0HïÐ~BÅ\x001f²$_-v&\x0014
«Ç\x0003Ðp8ö\x0015KEKhåYUÈ
ç\x0019ð\x000fÉ!\x0019aÏ~# \x0015¦Å$Ñéi-åÛ«#4ß¾ ¹\x001e^ÞG+çîà2O9\x0000ßHbËÙ\x0012/»\x0013</p><p>\x0006Õãè8\x001c{</p><p>ÙXCjÐ\x001bkXíèÌj\x0011\x0006GBsÒ°¤½K\x0008æåÒå´ø¥µ\x0002Blä1 (Às.\x0008äqÏ2êR¡½'ºhæ\x0017¶ë\x000c&Lyî!ëón;ÏËà\x0011@\x001aÅôÛ57%­-Ã;)\¹?0Ï®W÷}ªxmmàI!(ÞSºFD\x0000¹õ$uê:ænËçÎM\x001d¶£±¬6í\x0005ã8à\x001fÐz\x000clC(:ÕÂK<«2¸\x0011D\x0018á¢òÔä¯LoÝóú¹í@\x0016¯ml§Ì¾ÞD\x0016Ý2)\x0008;?JRÝår«\x0013H¹\x0003*û@É÷Ú@ú\x001fJäî.ZâÚþ\x001dòùoa<¯ºáÝ·®Ü\x0006\x0018\x000b\x001b\x000cÈ§\x001càb´ZuÌ®X}±Q¥óØ\x0005ìêËûÌä\x0002ûyÏ$÷Ï \x001bkkn/r°D·\x000e6´¡\x0006æ\x001cpO^Ãò¦µ«E,Mm	Vß"\x0018Æ\x001dºäçÍd[	.ç²K\x0001K6JWÌE\x0004d°äü¤\x0010ÀäúNkÉy#Zi÷\x0013Ü±KXä\x0008³\x0018\¹\x0019%\x0014
²±ãä<\x000c\x000eÍ@\x001bí\x0005´2Ëx A1_D.Àvàdô\x001c{</p><p>t)ncH\x0016"bd\x0003\x0001\x000e8R;p:z</p><p>©­J"´BÌÈ¬à\x0016ó(8'ç\x000c¨ã·SÐ­g%ÕßYã/ö¤i\x000cJXJHv¡-AÚ\x0014ç\x0004ç\x00064ÊÕüÖÐ·Ùñåf0|¾wÓ ééR\x0018b;³\x0012\x001dÌ\x001d²£\x0018Á>ã\x0003aT-¦ô»ÒÓ7¾XÄCs\x0004Æ\x0013båB¶\x000fñ1ãµc-ì¾EâE;¤HÖ¥^	ÞäüÒÅY-À\x0003\x0003# ¹\x0014\x0001ÔE\x000cPïò¢H÷±wØ ncÔSïM\x0016¶ë\x001c±¬\x0011\x0004B\x000c9=I\x001dóïX\x0012\(HÞL,
öÅ%fÝ\x001fK|ü»÷e³òàò6ñ Lvúéâ²?hÛ)£
\x0000ç\x0004\x0013É\x001cüÃq\x0000×k[(m4\x0016ñÛÛ5AE\x000b\x0019\x0019;aÜæ§Ù\x0005\x000b;p ;¢\x001eRþìç9^8ç+»\x0017\x0017zeá¼á]4åx\x0014\x001eaY2H\x0018ôÆ:zMÄ§U	
Âm\x0012Ä-Ë]¹gj\x0016"0\x0008\x001c¿ÎO\x001c¹\x0000\x001d\x001cFÑÈªèÀ«+\x000c\x000fPEW]>É-ÙlíÖÝÎæD»XñÉ\x0018ÇaùUm%±\x001c²MpîòÜÍ\x001a	\x001f\x0016GÂ¨ú\x0002}qì\x0000\x001at\x0001	µ·hâ ¤$4jPa\x0008è@íj%µ·9#\x0008¤IHgV@C\x0012;ô\x001f©¨ \x0008Ö\x0018$H¬7`\x0000Ç-ùO©¨Å¨ó1m\x0008ó7oýØù·cv}s\</p><p>±E\x0000W6V¦\x0006ÛBalnÆ6\x0000\x0006GN\x0000\x001f©\x0012\x0018£òöDå®ÄÂµxàz\x000e\x0007\x001eÂ¤¢\x001b\x001a$q¬qª¢(</p><p>ª£\x0000\x0001Ð\x0001QÁkol¸·(F6â4\x000bÆIÇ\x001eäÄÔÔP\x00042ÚÛÍ\x001cË\x0004R$¤3« !ÈÆ	\x001dú\x000fÈT\x001aª	-\x0018äøM:\x0000ª4û%Y\x0016ÎÜ<À¬"\¸=A8ç>õ3C\x0013,ªÑ!YÖ\x0002£\x000fÆ9õà\x0001ô©( </p><p>ÿ\x0000bµû/Ù~Í\x000fÙ¿ç6uÏNy§=­¼	\x0008P\x0002ïd\x0005°\x000eà3ì@?Z\x0000mmÒåîV\x0008áÆÖ ÜÃ	ëØ~Tä(ü½"ùk±0 m^8\x001eÇ°©( </p><p>÷6V·~Õm\x000cû3·Í63×\x0019úSÖÝîRå ®\x0010mYJ
Ê9à\x001e½ÏçSQ@\x0010­­º\½ÊÁ\x0012Ü8ÚÒ\x001bqÁ={\x000fÊ[{¸Äw0E:\x0003¸,\x0018\x0003ëSQ@\x0010Íko<É4\x0011Hñ\x001dÑ³ %\x000f¨'§AùS\x0018eV</p><p>Ëþ°\x0015\x0018~1Ï¯\x0000\x000f¥IE\x0000FðÅ'¾$o1v>T\x001dËÏ\x0007Ôrx÷5\x001c¶V³@Km\x000c¦6Fñ«ÐqV( \x0008fµ·Hä\x0008¤xèÙÐ\x0012Ô\x0013Ó üªGD@uV\x0000Ã\x000cò\x000eAü\x0008\x0006E\x0000WÊÖx¼©­¡=Åö<`Ç$\x001eü}ÍHðÄòÇ+Ä$YØåA)\x000e\x000flÔP\x0004"ÖÜNg\x0010D&b\x0018É°n$\x0002\x0001ÏÐô&£]>É&iÎÝes¹D»ä6IÇ¨\x0007ê*Õ%\x0000AöH¾Ú·@m+)À\x00006í¹'Ôü>é­mç9&)\x001e#º6t\x0004¡õ\x0004ôè?*\x0000¯-¬Ó¤òÛC$É<`²àä`õ\x001cÓ­­ÒÚ&\x000b\x0010]äù½Y\x001fÔ\x0000ímä¶\x0016Ï\x0004Mn\x0000_)\x0015Àè1Ó</p><p>rC\x0014~^È|µØP6¯\x001c\x000fAÀãØTP\x0004qÃ\x0014Xò¢DÂ\x001bT\x000fg\x0003è2p=ê\x0006Ó­ÖÊ[[xÒÖ9~ð4\x0000ç¯\x0004\x0010r8ät«tP\x0005K=>\x000bHÂ¨ó\x00186ýîª\x0008;v\x0002\x0000\x0000\x000c(\x000bÀ\x001c~4õ²µO?m´+öù¸\x000f3¯ÞõêzúÕ(\x0002\x0015µ·H^\x0015%ÆÖ@k\x000c\x0005Á\x001f@\x0007ÐQ\x0015­¼1Ç\x001cPE\x001aDK"ª\x0000\x0010äÛ©üÍME\x0000G<1\DÑO\x0012K\x001buGPÀ÷èhHbËÙ\x0012/»\x0013</p><p>\x0006Õãè8\x001c{</p><p>\x0000ÉÈò<¤òvìòö»qc¦1Ú£\x0016V¡´;U\x0014ùc* ä\x0001è\x0001\x0000ê*Å\x0014\x0001\x0018!·\x0011 ÚÅ×å\x001c1ÎH÷9<û +x("H£^\x0014\x000eý\x0005IE\x0000TNµ¥òáEX&(	´\x0016=1ßyÍ*éöIlöËgn¶îw4B%ÚÇHÆ;\x000fÊ­Q@
\x00128Ö8ÕQ\x0014\x0005UQ\x0000è\x0000¨RÊÕ\x0016EKhUeP\x0004`\x0007P0\x0001õ\x0000qJ±E\x0000C5­¼òG$ÐE#ÄwFÎ> \x0007åMÊÖiÒym¡dÆÉ\x001e0Ypr0zjÅ\x0014\x0001	µ·e Á\x0011\x00042Pr\x0018åây>´5­»Ü¥ËA\x0013\ Ú²\x001bsÀ={Î¦¢#\x0010Ä6â$\x001bXºü£9É\x001eç'sM¹µ·»Gs\x0004S ;È>¸55\x0014\x0000Ð$2\x0005Pì\x0002Ç$\x000càgñ? "	\x000cT;\x0000¥±É\x00038\x0019üOæiÔP\x0005x¬­aàÚ\x0018á|ï#\x0001[#\x0007#¡âº}[=²ÙÛ­»Í\x0010v±ã1Ãò«TP\x0003cD55TE\x0001UT`\x0000:\x0000*8ímâ¤\x0008Ø³\x0016T\x0000ØÉÏ¾\x0006~¦¢+Ëek4	\x0004¶ÐÉ</p><p>cdo\x0018*¸\x0018\x0018\x001d\x0007\x0014×Óì¤¹\x0017/gn×\x0000óZ%-Ðç\x0019ã\x0002­Q@\x0010ÜÚÛÝÆ#¹)Ð\x001dÁd@À\x001f\\x001asÃ\x0014fø¼ÅØùPw/<\x001fQÉãÜÔP\x0004~L^å'·g´nÛã=qÕ\x001aÙZ§¶Ú\x0015ûF|ÜF\x0007×ïzõ=}jÅ\x0014\x0001\x000cÖ¶óÉ\x001cA\x0014\x0011Ý\x001b:\x0002Púzt\x001fME\x0014\x0000QE\x0014\x0001ËQE\x0015óç´u4QE}\x0001â\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x0005\x0014Q@\x00056D\x0012FÈÅ`AÚÅOàG#ð§Q@
\x00128Ö8ÕQ\x0014\x0005UQ\x0000è\x0000¦Í\x000cs IWrW\x00038åH`0*J(\x00029!WÝrÑ6ô9èpW?\x001a(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¤¥¤ \x0005¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0000¢(\x0003¢+çÏlê¨¢ú\x0003Ä</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(¢</p><p>(®\x001bÆw×VÚÄI\x0005Ôð¡·S¶9YFw7<\x001f¥\!ÎìTcÌìw4Wkj\x001fô\x0010¼ÿ\x0000¿ïþ4kj\x001fô\x0010¼ÿ\x0000¿ïþ5·ÕßsObû³Ey7ö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGÕßpö/¹ë4Wkj\x001fô\x0010¼ÿ\x0000¿ïþ4kj\x001fô\x0010¼ÿ\x0000¿ïþ4}]÷\x000fbû³Ey7ö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGÕßpö/¹ë4Wkj\x001fô\x0010¼ÿ\x0000¿ïþ5Ûx*âk&wi&ap@i\x001c±\x0003jñQ:.</p><p>÷&TÜUÎ(¬LÂÈñLÒAáë©!âJaó¨ê+Ïµµ\x000fú\x0008^ß÷ÿ\x0000\x001aÖ\x0014Õîi\x0018s+³Ey7ö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãZ}]÷+Ø¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ%y?ö¶¡ÿ\x0000A\x000bÏûþÿ\x0000ãGöµÿ\x0000ý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÑõwÜ=îzÍ\x0015äßÚÚý\x0004/?ïûÿ\x0000\x001fÚÚý\x0004/?ïûÿ\x0000\x001fW}ÃØ¾ç¬Ñ^JÚ¶¡´ãP¼Î?ç»ÿ\x0000zÕeRäJ\x001c¡E\x0014Vd\x0005\x0015ÃxÎúêÛX º\x00146êvÇ+(Îæçô®û[Pÿ\x0000 çýÿ\x0000ñ­ãAÉ^æªjç¬Ñ^Mý­¨ÐBóþÿ\x0000¿øÑý­¨ÐBóþÿ\x0000¿øÕ}]÷\x001f±}ÏY¢¼û[Pÿ\x0000 çýÿ\x0000ñ£û[Pÿ\x0000 çýÿ\x0000ñ£êï¸{\x0017Üõ+É¿µµ\x000fú\x0008^ß÷ÿ\x0000\x001a?µµ\x000fú\x0008^ß÷ÿ\x0000\x001a>®û±}ÏY¢¼û[Pÿ\x0000 çýÿ\x0000ñ£û[Pÿ\x0000 çýÿ\x0000ñ£êï¸{\x0017Üõ+É¿µµ\x000fú\x0008^ß÷ÿ\x0000\x001a?µµ\x000fú\x0008^ß÷ÿ\x0000\x001a>®û±}ÏY¢¼û[Pÿ\x0000 çýÿ\x0000ñ£û[Pÿ\x0000 çýÿ\x0000ñ£êï¸{\x0017Üõ+ð=ÝÅÓ_ý¢âiöù\x0016Æwg\x0019ú</p><p>ë«	ÇØÊJÎÁE\x0014T(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000åh¢ùóÛ:ª(¢¾ñ\x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002( \x0002¼ïÇír\x001fúö_ý	«Ñ+Í¾"¶5Ëúö\x001fú\x0013VÔ>3J_\x0011Îo£}VßFúî:Nÿ\x0000U·¶K­i\x0004vo\x0014\x0016À¥¼0\x00056!pù</p><p>2 ä\x0013yôªí é¶·âÞy<rÂ
Âf}ø
\x0003r`{ä~c:Õó_ËzÓæâUÙ!(¸uÆ0W\x0018#\x0000qtºî£4{^å%\x000b:¨Wr¿t³\x0001Ç¹53å}ÎM*Æ[Ë]fXäÕ>ÄÆê¡3Õ¾éÈô\x0018\x0018õ4EáÛo·i¶ÒM3}¦KäeÀÿ\x0000TH\x0004\x000c\x001cg\x001dó\òxPIdL¤LA\x0008\x0012\x000fã\x0000\x0006÷\x001c-¼C©Úìò¯\x001c\x0014fpX\x00069o½É\x0004àqÓ<õæY÷\x001d¥Ü¹«ÚÛXÁb"\x0013\x0019®-£¸fg\x001bFàr\x0000Ûê:æ²÷Ón¯ç»ò|ù7ù1,)À\x0018AÐqPo­RijZó,ï¯Cð\x0001Î9ÿ\x0000§ÿ\x0000ÐV¼Ï}zWÃ³\x0006cÿ\x0000O-ÿ\x0000 ­e_à3«ð]\x0014Q\'1ã\x001e<1yÿ\x0000\x0000ÿ\x0000ÐÖ¼¿}zøðµïÑ?ô5¯'ß]è¥±g}tZx|,×\x001b¬áí»<Û<Ì®ÀvýÖïÏJå7ÕË}^êÚÐÚÆÑ4\x0005üÍB
ØÆ~`{VÒM­
\x001a¹ÒZh¶w£N/<~ gÃD F</p><p>\x0013\x0003\x0000ã»×¨Æ\x000b#Ñm%Ô4%iÕï-ÒâI\x000b\x0000*Ä¨\x0018ÿ\x0000g®OÐÖ\x0014zíüR[<sª\x001bbæ\x001d±¨	¿ï`c\x001cçðíQÿ\x0000l^ý¦Öà\0Õ\x00168X\x00006¨è:sÔõëÞ£]É´»</p><p>hÖ2/·\x0007\x0011ÚÍ<Öé:JÊP
ê03zv?ÒèöPiJ·\x0012,Mok1HÕùA8Á#\x0000g\x0000ûdÖ
·.cZc¾%¢\x0011F\x00165</p><p>Ç'\x000b´¯=ò§?P\x0008Pñ-åÓb\x0017x#ò¢å·;yg*Åð\x000eíÄRå÷\x000bHèì´;\x0008õ?ÜÍqm,#ÍI!j\x0004\x00079\x0004\x0015#R\x0001\x0007'û6Íìô¦ÏYu)Z5,à¬@H\x0017´nàúk)üA©4±È.v<r¹à±</p><p>\x0000bG\x001cç©õ¨%ÕnåKtiv­»3Â\x0011Bl,w\x001c`\x000csùv¦£.à»\~\x001fÓ¥Ô¢µ\x0017.nd¢\x0017\x0011ÈåU	\x000fÀùy\\x0010GzÎðÚÛ]xÚ?#u»nýÜÄIü\x0007¯\x0000\x001e}«;þ\x0012=LN-Â££´dH »\x000c\x0016 \x000c\x0013ç5NÊþ{\x000b¤¹µË3µ°\x000e20x<t4rÊÎì,ìtèÖpéÉ$·>\Ïd.Úd\x0001ò#\x0011ýãÇ|õü©t«K;­\x0002\x000f´#\x0007RX\x0003Æ\x0000|\x0015\x001cn=\x0000Î{ô÷ÈÁþÚ¾û/Ùüÿ\x0000Ýù^Nv.ÿ\x0000/9Ù¿\x001b¶ûg\x001d¨³Ö¯¬`\x0010[O²!/´¢¿\x0018\x0004äsÐ~ \x001e¢Y[p³±»u¢Û[\x0008<ÉâîæK7 "ífvã'#¶êµmáë\x001b«µD{ã[Ùm\x001c\x0017V-µ\x000b\x0006\x0007hÇN?Zå%Õo&KuáÛììÏ\x0013tef;ÝÔóS¿5&9\x0005ÎÇS0òÑP\x0017<\x0016!@\x000cHãõ>´8Ï¸Z]ÍÛ
*\x0006Ñó{ùÙ\ÊÀª0\x0005\x0018\x0001©Ç^£B+jÿ\x0000F´»¹{T;pÚ¦ø£\x0000\x0016áÊLù×\x0010Þ Ô/(ÜþïÊxBì\\x0004|nQÇ\x0003L`bþ#Õ\x001eO0Ý°8O>p»sÀþï\x0018èi8M»ÜN26í´[\x001b(ï<Ë¡Òy¶e]£`:àd\x0010zqÓ­R¼ÒâMOM·GXïãA¿\x000ccÞq1~\x0015uÛò</p><p>ÕPÂÐlHÕT#\x001c°</p><p>\x0006\x0006OqÍA6¥u<ï$Í¾Ù\x00168p¥\x0015z`O^µIJû;;
\x0017KMb\x0018Ý¼Ç["û;Ü$©`ä(È\x0019R</p><p>QCÏéö_Ã©\x00142$°Bg\x0016\x0005v)ù\x001crpF0\x00075QüA©4±È.v<r¹à±</p><p>\x0000bG\x001cç©õ¥ÒµuÓ¯ÚøÁæÜÆ<0DRA\x0007*\x0007#d¬Ñ²-·ü$öÚCÉ7ú±ç°#ïì,v}ÞFzÓtí2ÆîËí²4@×K\x0006×¹Dò×nY2áºô\x0000\x001f­`CªÝÁ¨øåÛtYÉ´\x001e[9ã\x0018îiÖz½å{-åPÄ^5p®:0\x000c\x000e\x000f¸¦ã.ã³ît@´ób.$À[Í,®¤oc\x0011ÚÅ8#\x0004#'¦y©.<=c\x0005Ùµ{¢²¤°GÌÑ9\x0001°S\x0019Ï9ãó®_ûb÷ì3Ùh.\x001fÌX\x0002]²\x000eI#=z¼A©6Òn~`Èå(g)÷w\x001ce±þÖirÏ¸­.çQa¡Yµú\x0018ej^Ëhþb£nÛ\x0019`@ 1AÏ^:V\x001e¯kmc\x0005Lf¸¶ám\x001bÈ\x0003o¨ë§\x000f5(\x001c¼w;XÎ×\x0004ìSûÆ\x0005IéèO\x001d*­Õü÷~O&ÿ\x0000&%8\x0003\x0008:\x000e)¨Êú±¤ï©Ó>göYÄÿ\x0000Ùû\x0015\x0007¸õ9ý1ß<]Ö´kFÔK hDV"\x0001T+F¤1×&¹Ëß\x0011\Ü[Co	h"KT¶p\x0008;ÀêAÆW<d\x000e¸\x0019ÍGÿ\x0000	\x001e©ç¼ßko1Ýd'bðÊ0\x0008ã88ê89©å÷&Ò7SB²\¤2Os42Ì\x0014N¾dJ¤m
ý³:àsTtÈ­dðö±<°³Ï\x0008#îû»°Ç¨çÔqÇ5¾ Ôq\x0017?1gpÅ\x0014²\x0017ûÛN2¹ÿ\x0000g\x0015VÞþ{h§)1\x001cë²D \x0010Ã·\x0007¸ìzÕ\²êÊ³:¸¼=m$#{Í\x000cÉ$\x0002HÙÁ}²>ßvüG8Ëc½U}6Ä\x001d^M×)\x000eË\x00167+31r»º\x000e\x0000\x0019ÛßÔVWü$zÒ>Ð¹%\x000b?¡\x0005K62ØÀêj\x0008õØ¦¹;W¹;¥ \x000fç9Æ8 ò\x0008ävÅ%\x0019÷\x0015¤jø©"·ñ\x0015ÜPÆF»0 \x0001ò)è+\x001f}6öþ{û§¹ºÌñ¹°\x0006p08\x001ct\x0015\x0006ú¸«$IY\x0016KäW¶W«åÖ½Ò¹ñ\x001d\x000c«t</p><p>(¢¹L\x000f;ñûc\þ½ÿ\x0000Bjå÷×Gñ\x0015±®[ÿ\x0000×°ÿ\x0000Ð¹=õèRø\x0011×\x000f\x0016w×O K­;@F\x0008Íü¯\x001cÏ\x0014\x0011«\x0010$\x0000`ãJã÷Õ¥ÕnÕ,ÐKòÙ1x\x0006Ñò\x0012w\x001eÜò;ÕI_aµspiÖm¨ßÄ\x0012u¶³%dI¨Á#qm®\x0000</p><p>\x0014Iç¿?lmf),×/ôµ]»GÊè¬3ÇQ»¯|t\x0019Èå£Õï#æA*±º9^5esä©\x0018ëíÅK75)Ü<;N·\x0000ìQûÅ\x0001Aéè\x0007\x001d*\x001cgÜK¹»\x000ehñN4×w0É*K\x001c\x000c¡ã\x000bÀa\x0019ûàtaÔ\x0001NM\x0013O(¢In0_1]¤)ô\x0003¿ÓNxÀ_\x0010jK¸³¸bY\x000býí§\x0019\ÿ\x0000³göÕ÷ü÷ÿ\x0000o²}Åÿ\x0000UýÞ¯_z9gÜ-.çDt\x000ba\x0004Aäh¬\x0013¬M2FA#\x000cqØg#ñ´ºf\x0014\x0011Æo\x0011õ(íÄÉ(ù\\x000f\x0003v\x0008\x0018$äp\x0007*5Ûð\x0002ÕB°lxÕ¢¨*F\x000e\x000fsÍ6MoPÍó.²d8èÊöã\x001cqÒ,PåswU²±ÛP½\x0011Ì¬·ïm\x001ci"\.s½38ã÷£XÑ¬ôè.Ô\ââÛËÚ\x001ad&}ÀnÂ\x000fqó?:ÀºÕï.á)åVI¼öQ\x001a®_\x0018ÝÀôÿ\x0000\x001auÎµ}u\x0003C4ûöù"hÂî`2Ø÷&´Ô\x0012d[èßU·Ñ¾µ,ï¾\x001dGþÙìõÛ×\x000bðÔåu/¬û5wUÁ[ãg-O\x0014QY\x0010\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000r´RQ_<{gWE\x0014WÐ QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000QE\x0014\x0000Vn£¡iº¤ë5í°E]a{\x001fsZTSM­¶0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢<»÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ£þ\x0010ý\x0007þ|\x0007ýüñ­Ú(çpæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000Æ´´í:ÓK·0YEåDÍ¼®âyÀ\x001dÏ°«tPäÞìM·¸QE\x0015" ½³þÕí®£ó!\x001b$g\x0007=½Ådÿ\x0000Â\x001f ÿ\x0000Ïÿ\x0000¿þ5»ER[1¦ÖÆ\x0017ü!ú\x000füø\x000fûøÿ\x0000ãGü!ú\x000füø\x000fûøÿ\x0000ã[´QÏ.ãæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000ÆøCô\x001fùð\x001f÷ñÿ\x0000Æ·h£]Ã÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ£þ\x0010ý\x0007þ|\x0007ýüñ­Ú(çpæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000ÆøCô\x001fùð\x001f÷ñÿ\x0000Æ·h£]Ã÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ£þ\x0010ý\x0007þ|\x0007ýüñ­Ú(çpæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000ÆøCô\x001fùð\x001f÷ñÿ\x0000Æ·h£]Ã÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ¤ÿ\x0000CBÿ\x0000\x0001ÿ\x0000\x001fükzyw\x000egÜÃÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ£þ\x0010ý\x0007þ|\x0007ýüñ­Ú(çpæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000ÆøCô\x001fùð\x001f÷ñÿ\x0000Æ·h£]Ã÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000CBÿ\x0000\x0001ÿ\x0000_ükv)97¸op¢)\x0008ÍÔt-7Tf½¶\x0013H«°\x0012ì02Ocîj§ü!ú\x000füø\x000fûøÿ\x0000ã[´U)ÉlÇÌû_ðè?óà?ïãÿ\x0000\x001fðè?óà?ïãÿ\x0000nÑG<»÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜÂÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fühÿ\x0000?Aÿ\x0000\x0001ÿ\x0000\x001fükv9åÜ9s\x000bþ\x0010ý\x0007þ|\x0007ýüñ£þ\x0010ý\x0007þ|\x0007ýüñ­Ú(çpæ}Ì/øCô\x001fùð\x001f÷ñÿ\x0000ÆøCô\x001fùð\x001f÷ñÿ\x0000Æ·h£]Ã÷0¿á\x000fÐçÀßÇÿ\x0000\x001a?á\x000fÐçÀßÇÿ\x0000\x001aÝ¢yw\x000egÜ¡¦é\x0016:Wö\x0018\x0004>n7üÌsã©>¦¯ÑE&ÛÕÝÂ(¤\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0001E\x0014P\x0007)E\x0014WÏ\x001eáÕÑE\x0015ô'\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014´\x0000´QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000\x0014QE\x0000rRQ_:{ö½Ç÷"üøÑý¯qýÈ¿#þ5RA\x0017(MÁr	Éè03[ªõ[²£M+´\þ×¸þä_ÿ\x0000\x001a?µî?¹\x0017äÆªE\x0003Hd\x0007äòÔÜ\x000e^?CL1¸@å\x0018!à684ýµk^ì=-¬ßÚ÷\x001fÜò?ãGö½Ç÷"üøÕ4·äDØÀ¹ÀÈ?åM1·\x0003kn,W\x001b{ú}höÕ»°öT»"÷ö½Ç÷"üøÑý¯qýÈ¿#þ5KÊyM¸u\x0018çüò)\x0016)\x0019Ê*1aÔ\x0001È£ÛÖîÿ\x0000¯{*]{û^ãû~Gühþ×¸þä_ÿ\x0000\x001a£\x0012y"g\x001b.}3J±±¤Ãm^2\x0014¯ùíB¯Yý¦\x000e%Ð»ý¯qýÈ¿#þ4kÜr/Èÿ\x0000Qòß`m´óqéOH\x001d¤YY\x0004\x0000ÄuÏz\x0015jÏ«\x000feItE¿í{îEù\x001fñ£û^ãû~GüjG(\#\x0014\x001c\x0016Ç\x0002\x001b\x000eQ\x001e\x0003cKÛÖîÃØÒìßÚ÷\x001fÜò?ãGö½Ç÷"üøÖ}H±\x0016L]Ø'nyÀëíëB¯Uí ti®Ïí{îEù\x001fñ£û^ãû~Güjqï\x0005*(ÀËg©ú}
\x0002&2Î\x0003.sØëOÛVîÃÙRì]þ×¸þä_ÿ\x0000\x001aQ¬O`Æ©4,\x0018\x0005ùÁ\x0019\x0005Aç>)¾[áNÆÃð¼uúQíë.¬=.Èèm/#º_åqÕMY®d+Áp :«6ìð8ÍoÛN'\x001c©ldã¡÷çèkÐÃ×s÷e¹Å^±Ø(®£(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000(¢\x0000äè¢ùÓÜ</p><p>\x0006\x0008ä±ÀØÃóR*:)§gpjêÅ¿=\x000eÞÄ£\x0017>­·hÏ¯¯ü\x0008ÒI*\x0018NÝ\x0015\x000f
»~\x001dª­\x0015~ÑìÑwí\x0008n]ÙÉ\x0006upN~èÏÿ\x0000Z£DDT,\x000e\x000c \x001cr \x0003U¨£Ú0öh²eT_$E³#8?></p>
  
### Reference
* http://blogs.wsj.com/cio/2013/10/08/adobe-source-code-leak-is-bad-news-for-u-s-government/

  
#### CWE Id : 540
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Vulnerable JS Library
##### Medium (Medium)
  
  
  
  
#### Description
<p>The identified library jquery, version 1.11.0 is vulnerable.</p>
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `jquery-1.11.0.js`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-ui-1.10.4.custom.js](https://www.impots.nc/statics/public/theme/js/jquery-ui-1.10.4.custom.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `/*! jQuery UI - v1.10.4 - 2014-02-02
* http://jqueryui.com
* Includes: jquery.ui.core.js, jquery.ui.widget.js, jquery.ui.mouse.js, jquery.ui.position.js, jquery.ui.draggable.js, jquery.ui.droppable.js, jquery.ui.resizable.js, jquery.ui.selectable.js, jquery.ui.sortable.js, jquery.ui.accordion.js, jquery.ui.autocomplete.js, jquery.ui.button.js, jquery.ui.datepicker.js, jquery.ui.dialog.js`
  
  
  
  
Instances: 2
  
### Solution
<p>Please upgrade to the latest version of jquery.</p>
  
### Other information
<p>CVE-2020-11023</p><p>CVE-2020-11022</p><p>CVE-2015-9251</p><p>CVE-2019-11358</p><p></p>
  
### Reference
* https://github.com/jquery/jquery/issues/2432
* http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/
* http://research.insecurelabs.org/jquery/test/
* https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/
* https://nvd.nist.gov/vuln/detail/CVE-2019-11358
* https://nvd.nist.gov/vuln/detail/CVE-2015-9251
* https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b
* https://bugs.jquery.com/ticket/11974
* https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
* 

  
#### CWE Id : 829
  
#### Source ID : 3

  
  
  
  
### X-Frame-Options Header Not Set
##### Medium (Medium)
  
  
  
  
#### Description
<p>X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.</p>
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesGerantDeSociete.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesGerantDeSociete.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-GEN-SEL/informations-legales.html](https://www.impots.nc/statics/public/infobulle/CU-GEN-SEL/informations-legales.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Frame-Options`
  
  
  
  
Instances: 11
  
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
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Evidence: `<form id="form" action="/sel/public/contact.do" method="post">`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form id="form" action="/sel/public/contact.do" method="post">`
  
  
  
  
Instances: 2
  
### Solution
<p>Phase: Architecture and Design</p><p>Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.</p><p>For example, use anti-CSRF packages such as the OWASP CSRFGuard.</p><p></p><p>Phase: Implementation</p><p>Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.</p><p></p><p>Phase: Architecture and Design</p><p>Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Use the ESAPI Session Management control.</p><p>This control includes a component for CSRF.</p><p></p><p>Do not use the GET method for any request that triggers a state change.</p><p></p><p>Phase: Implementation</p><p>Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.</p>
  
### Other information
<p>No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF] was found in the following HTML form: [Form 1: "_sendToSelf" "captcha-input-id-value" "captchaComplexityId" "edit-submitted-email" "espace-date-naissance" "espace-nom" "espace-prenom" "espace-send-to-self" "id-captcha-erreur" "op" "typeCaptcha" ].</p>
  
### Reference
* http://projects.webappsec.org/Cross-Site-Request-Forgery
* http://cwe.mitre.org/data/definitions/352.html

  
#### CWE Id : 352
  
#### WASC Id : 9
  
#### Source ID : 3

  
  
  
  
### Cookie No HttpOnly Flag
##### Low (Medium)
  
  
  
  
#### Description
<p>A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible.</p>
  
  
  
* URL: [https://www.impots.nc/sel/public/captcha/image.do](https://www.impots.nc/sel/public/captcha/image.do)
  
  
  * Method: `GET`
  
  
  * Parameter: `CaptchaId`
  
  
  * Evidence: `Set-Cookie: CaptchaId`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/captcha/audio.wav](https://www.impots.nc/sel/public/captcha/audio.wav)
  
  
  * Method: `GET`
  
  
  * Parameter: `CaptchaId`
  
  
  * Evidence: `Set-Cookie: CaptchaId`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that the HttpOnly flag is set for all cookies.</p>
  
### Reference
* https://owasp.org/www-community/HttpOnly

  
#### CWE Id : 1004
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Cookie without SameSite Attribute
##### Low (Medium)
  
  
  
  
#### Description
<p>A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.</p>
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/](https://www.impots.nc/sel/public/)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/captcha/audio.wav](https://www.impots.nc/sel/public/captcha/audio.wav)
  
  
  * Method: `GET`
  
  
  * Parameter: `CaptchaId`
  
  
  * Evidence: `Set-Cookie: CaptchaId`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/captcha/image.do](https://www.impots.nc/sel/public/captcha/image.do)
  
  
  * Method: `GET`
  
  
  * Parameter: `CaptchaId`
  
  
  * Evidence: `Set-Cookie: CaptchaId`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [https://www.impots.nc/sel/](https://www.impots.nc/sel/)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
Instances: 8
  
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
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/captcha/audio.wav](https://www.impots.nc/sel/public/captcha/audio.wav)
  
  
  * Method: `GET`
  
  
  * Parameter: `CaptchaId`
  
  
  * Evidence: `Set-Cookie: CaptchaId`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/captcha/image.do](https://www.impots.nc/sel/public/captcha/image.do)
  
  
  * Method: `GET`
  
  
  * Parameter: `CaptchaId`
  
  
  * Evidence: `Set-Cookie: CaptchaId`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/](https://www.impots.nc/sel/public/)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [https://www.impots.nc/sel/](https://www.impots.nc/sel/)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
Instances: 8
  
### Solution
<p>Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such sensitive information.</p>
  
### Reference
* https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html

  
#### CWE Id : 614
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Dangerous JS Functions
##### Low (Low)
  
  
  
  
#### Description
<p>A dangerous JS function seems to be in use that would leave the site vulnerable.</p>
  
  
  
* URL: [https://www.impots.nc/sel/public/bundles/js/67926014/base.js](https://www.impots.nc/sel/public/bundles/js/67926014/base.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `eval`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `eval`
  
  
  
  
Instances: 2
  
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
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesGerantDeSociete.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesGerantDeSociete.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-GEN-SEL/informations-legales.html](https://www.impots.nc/statics/public/infobulle/CU-GEN-SEL/informations-legales.html)
  
  
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

  
  
  
  
### In Page Banner Information Leak
##### Low (High)
  
  
  
  
#### Description
<p>The server returned a version banner string in the response content. Such information leaks may allow attackers to further target specific issues impacting the product and version in use.</p>
  
  
  
* URL: [https://www.impots.nc/robots.txt](https://www.impots.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  * Evidence: `Tomcat/8.0.39`
  
  
  
  
* URL: [https://www.impots.nc/sitemap.xml](https://www.impots.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  * Evidence: `Tomcat/8.0.39`
  
  
  
  
Instances: 2
  
### Solution
<p>Configure the server to prevent such information leaks. For example:</p><p>Under Tomcat this is done via the "server" directive and implementation of custom error pages.</p><p>Under Apache this is done via the "ServerSignature" and "ServerTokens" directives.</p>
  
### Other information
<p>There is a chance that the highlight in the finding is on a value in the headers, versus the actual matched string in the response body.</p>
  
### Reference
* https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Permissions Policy Header Not Set
##### Low (Medium)
  
  
  
  
#### Description
<p>Permissions Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Permissions Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.</p>
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sitemap.xml](https://www.impots.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/robots.txt](https://www.impots.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/](https://www.impots.nc/sel/public/)
  
  
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
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/robots.txt](https://www.impots.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/authorize.do](https://www.impots.nc/sel/public/authorize.do)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/](https://www.impots.nc/sel/public/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sitemap.xml](https://www.impots.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html)
  
  
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
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-GEN-SEL/informations-legales.html](https://www.impots.nc/statics/public/infobulle/CU-GEN-SEL/informations-legales.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/favicon.ico](https://www.impots.nc/sel/public/favicon.ico)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.Notices.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesGerantDeSociete.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesGerantDeSociete.html)
  
  
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
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sel/public/bundles/css/N161715471/base`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesGerantDeSociete.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesGerantDeSociete.html)
  
  
  * Method: `GET`
  
  
  * Evidence: `org/TR/xhtml1/DTD/xhtml1-strict`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html)
  
  
  * Method: `GET`
  
  
  * Evidence: `org/TR/xhtml1/DTD/xhtml1-strict`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sel/public/bundles/css/N161715471/base`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sel/public/bundles/css/N161715471/base`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.VousEtesTravailleurIndependant.html)
  
  
  * Method: `GET`
  
  
  * Evidence: `org/TR/xhtml1/DTD/xhtml1-strict`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/Creer-mon-compte-personnel.pdf](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/Creer-mon-compte-personnel.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `/Encoding/WinAnsiEncoding/Subtype/Type1`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/](https://www.impots.nc/sel/public/)
  
  
  * Method: `GET`
  
  
  * Evidence: `/sel/public/bundles/css/N161715471/base`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL.DECONNECTE/IHM.ACCUEIL.EnSavoirPlus.html)
  
  
  * Method: `GET`
  
  
  * Evidence: `org/TR/xhtml1/DTD/xhtml1-strict`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.QuestionsFrequentes.html)
  
  
  * Method: `GET`
  
  
  * Evidence: `org/TR/xhtml1/DTD/xhtml1-strict`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/bundles/js/67926014/base.js](https://www.impots.nc/sel/public/bundles/js/67926014/base.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `D27CDB6E-AE6D-11cf-96B8-444553540000`
  
  
  
  
Instances: 11
  
### Solution
<p>Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.</p>
  
### Other information
<p>�ǥ����'?n�ݕ�?r�?7^��^x�_�j�</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Low)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [https://www.impots.nc/sel/public/bundles/js/67926014/base.js](https://www.impots.nc/sel/public/bundles/js/67926014/base.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `later`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `where`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `bugs`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/bundles/js/67926014/base.js](https://www.impots.nc/sel/public/bundles/js/67926014/base.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `username`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `later`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/bundles/js/67926014/base.js](https://www.impots.nc/sel/public/bundles/js/67926014/base.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `select`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `username`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/bundles/js/67926014/base.js](https://www.impots.nc/sel/public/bundles/js/67926014/base.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/](https://www.impots.nc/sel/public/)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `select`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `bug`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/bundles/js/67926014/base.js](https://www.impots.nc/sel/public/bundles/js/67926014/base.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
Instances: 18
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bLATER\b and was detected in the element starting with: "return Math.ceil(value);},getValue=function(value,dim){return getScalar(value,dim)+'px';};$.extend(F,{version:'2.1.4',defaults:{", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Modern Web Application
##### Informational (Medium)
  
  
  
  
#### Description
<p>The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.</p>
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/IHM.ACCUEIL.VideosExplicatives.html)
  
  
  * Method: `GET`
  
  
  * Evidence: `<script type="text/javascript" src="../../theme/js/jquery-1.11.0.js"></script>`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/Declarer-l-IRVM.pdf](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/Declarer-l-IRVM.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `<A>`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/](https://www.impots.nc/sel/public/)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="#"><img alt="Logo mobile de NC Connect" src="/sel/public/images/icons/logo-color.svg"/><div>Se connecter</div></a>`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="#"><img alt="Logo mobile de NC Connect" src="/sel/public/images/icons/logo-color.svg"/><div>Se connecter</div></a>`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/bundles/js/67926014/base.js](https://www.impots.nc/sel/public/bundles/js/67926014/base.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a id='"+expando+"'></a>`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/Demander-un-etat-hypothecaire.pdf](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/Demander-un-etat-hypothecaire.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `<A>`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js](https://www.impots.nc/statics/public/theme/js/jquery-1.11.0.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href='#'></a>`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="#"><img alt="Logo mobile de NC Connect" src="/sel/public/images/icons/logo-color.svg"/><div>Se connecter</div></a>`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a href="#"><img alt="Logo mobile de NC Connect" src="/sel/public/images/icons/logo-color.svg"/><div>Se connecter</div></a>`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/theme/js/jquery-ui-1.10.4.custom.js](https://www.impots.nc/statics/public/theme/js/jquery-ui-1.10.4.custom.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `<a>" ).outerWidth( 1 ).jquery ) {
	$.each( [ "Width", "Height" ], function( i, name ) {
		var side = name === "Width" ? [ "Left", "Right" ] : [ "Top", "Bottom" ],
			type = name.toLowerCase(),
			orig = {
				innerWidth: $.fn.innerWidth,
				innerHeight: $.fn.innerHeight,
				outerWidth: $.fn.outerWidth,
				outerHeight: $.fn.outerHeight
			};

		function reduce( elem, size, border, margin ) {
			$.each( side, function() {
				size -= parseFloat( $.css( elem, "padding" + this ) ) || 0;
				if ( border ) {
					size -= parseFloat( $.css( elem, "border" + this + "Width" ) ) || 0;
				}
				if ( margin ) {
					size -= parseFloat( $.css( elem, "margin" + this ) ) || 0;
				}
			});
			return size;
		}

		$.fn[ "inner" + name ] = function( size ) {
			if ( size === undefined ) {
				return orig[ "inner" + name ].call( this );
			}

			return this.each(function() {
				$( this ).css( type, reduce( this, size ) + "px" );
			});
		};

		$.fn[ "outer" + name] = function( size, margin ) {
			if ( typeof size !== "number" ) {
				return orig[ "outer" + name ].call( this, size );
			}

			return this.each(function() {
				$( this).css( type, reduce( this, size, true, margin ) + "px" );
			});
		};
	});
}

// support: jQuery <1.8
if ( !$.fn.addBack ) {
	$.fn.addBack = function( selector ) {
		return this.add( selector == null ?
			this.prevObject : this.prevObject.filter( selector )
		);
	};
}

// support: jQuery 1.6.1, 1.6.2 (http://bugs.jquery.com/ticket/9413)
if ( $( "`
  
  
  
  
* URL: [https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/S_abonner-au-teleservice-vos-demarches-fiscales-en-ligne.pdf](https://www.impots.nc/statics/public/infobulle/CU-SEL-ACCUEIL/S_abonner-au-teleservice-vos-demarches-fiscales-en-ligne.pdf)
  
  
  * Method: `GET`
  
  
  * Evidence: `<A>`
  
  
  
  
Instances: 11
  
### Solution
<p>This is an informational alert and so no changes are required.</p>
  
### Other information
<p>No links have been found while there are scripts, which is an indication that this is a modern web application.</p>
  
### Reference
* 

  
#### Source ID : 3

  
  
  
  
### Non-Storable Content
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.</p>
  
  
  
* URL: [https://www.impots.nc/sel/public](https://www.impots.nc/sel/public)
  
  
  * Method: `GET`
  
  
  * Evidence: `302`
  
  
  
  
* URL: [https://www.impots.nc/sel](https://www.impots.nc/sel)
  
  
  * Method: `GET`
  
  
  * Evidence: `302`
  
  
  
  
* URL: [https://www.impots.nc/sel/](https://www.impots.nc/sel/)
  
  
  * Method: `GET`
  
  
  * Evidence: `302`
  
  
  
  
Instances: 3
  
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
  
  
  
* URL: [https://www.impots.nc/robots.txt](https://www.impots.nc/robots.txt)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc](https://www.impots.nc)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/sitemap.xml](https://www.impots.nc/sitemap.xml)
  
  
  * Method: `GET`
  
  
  
  
* URL: [https://www.impots.nc/](https://www.impots.nc/)
  
  
  * Method: `GET`
  
  
  
  
Instances: 6
  
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
  
  
  
* URL: [https://www.impots.nc/sel/public/](https://www.impots.nc/sel/public/)
  
  
  * Method: `GET`
  
  
  * Evidence: `67926014`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Evidence: `67926014`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Evidence: `545067891`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Evidence: `67926014`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/](https://www.impots.nc/sel/public/)
  
  
  * Method: `GET`
  
  
  * Evidence: `545067891`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Evidence: `545067891`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Evidence: `67926014`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Evidence: `134537135`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `GET`
  
  
  * Evidence: `855561965`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Evidence: `1292375258`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1](https://www.impots.nc/sel/public/index.do;jsessionid=F968A1BA2E29F26F86447E72EBC90B6C.tomcat1)
  
  
  * Method: `GET`
  
  
  * Evidence: `1292375258`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3](https://www.impots.nc/sel/public/index.do;jsessionid=5166A7037B10DB0811D069E1B73031B4.tomcat3)
  
  
  * Method: `GET`
  
  
  * Evidence: `545067891`
  
  
  
  
Instances: 12
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>67926014, which evaluates to: 1972-02-26 04:20:14</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### User Controllable HTML Element Attribute (Potential XSS)
##### Informational (Low)
  
  
  
  
#### Description
<p>This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.</p>
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `typeCaptcha`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `typeCaptcha`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `captchaComplexity`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `prenom`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `typeCaptcha`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `typeCaptcha`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `sendToSelf`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `dateNaissance`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `nomNaissance`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `sendToSelf`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `op`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `captchaComplexity`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `typeCaptcha`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `_sendToSelf`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `captchaComplexity`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `captchaComplexity`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `captchaValue`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `addresseMail`
  
  
  
  
* URL: [https://www.impots.nc/sel/public/contact.do](https://www.impots.nc/sel/public/contact.do)
  
  
  * Method: `POST`
  
  
  * Parameter: `captchaComplexity`
  
  
  
  
Instances: 19
  
### Solution
<p>Validate all input and sanitize output it before writing to any HTML attributes.</p>
  
### Other information
<p>User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:</p><p></p><p>https://www.impots.nc/sel/public/contact.do</p><p></p><p>appears to include user input in: </p><p></p><p>a(n) [input] tag [type] attribute </p><p></p><p>The user input found was:</p><p>typeCaptcha=text</p><p></p><p>The user-controlled value was:</p><p>text</p>
  
### Reference
* http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-html-attribute

  
#### CWE Id : 20
  
#### WASC Id : 20
  
#### Source ID : 3
