/*** Based on
https://github.com/arkenfox/user.js
https://github.com/pyllyukko/user.js

Installation
Windows 7 	%APPDATA%\Mozilla\Firefox\Profiles\XXXXXXXX.your_profile_name\user.js
Linux 	~/.mozilla/firefox/XXXXXXXX.your_profile_name/user.js
OS X 	~/Library/Application Support/Firefox/Profiles/XXXXXXXX.your_profile_name
Android 	/data/data/org.mozilla.firefox/files/mozilla/XXXXXXXX.your_profile_name and see issue #14
Sailfish OS + Alien Dalvik 	/opt/alien/data/data/org.mozilla.firefox/files/mozilla/XXXXXXXX.your_profile_name
Windows (portable) 	[firefox directory]\Data\profile\
***/

user_pref("browser.aboutConfig.showWarning", false);

/*** Bloat ***/
user_pref("browser.translations.enable", false);
user_pref("browser.vpn_promo.enabled", false); //  Disable Mozilla VPN ads on the about:protections page
user_pref("browser.offline-apps.notify", true); //  Display a notification bar when websites offer data for offline use
user_pref("browser.pocket.enabled", false); //  Disable Pocket
user_pref("extensions.pocket.enabled", false);

/*** OVERRIDE ***/
user_pref("browser.search.countryCode", "US"); //  Disable GeoIP lookup on your address to set default search engine region
user_pref("browser.search.region", "US");
//user_pref("browser.search.geoip.url", "");
user_pref("intl.accept_languages", "en-US, en"); //  Set Accept-Language HTTP header to en-US regardless of Firefox localization
user_pref("intl.locale.matchOS", false); //  Don't use OS values to determine locale, force using Firefox locale setting
user_pref("browser.search.geoSpecificDefaults", false); // Use LANG environment variable to choose locale (disabled)
user_pref("general.buildID.override", "20100101"); //  Don't reveal build ID
user_pref("browser.startup.homepage_override.buildID", "20100101");

/*** INFORMATION LEAKING ***/
user_pref("dom.netinfo.enabled", false); //  Disable leaking network/browser connection information via Javascript
user_pref("dom.vr.enabled", false); //  Disable virtual reality devices APIs
user_pref("dom.vibrator.enabled",  false); //  Disable vibrator API
user_pref("dom.gamepad.enabled", false); //  Disable gamepad API to prevent USB device enumeration
user_pref("dom.maxHardwareConcurrency", 2); //  Spoof dual-core CPU
user_pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled", false); //  Disable sending Flash Player crash reports
user_pref("dom.ipc.plugins.reportCrashURL", false); //  When Flash crash reports are enabled, don't send the visited URL in the crash report
user_pref("dom.flyweb.enabled", false); //  Disable FlyWeb (discovery of LAN/proximity IoT devices that expose a Web interface)
user_pref("beacon.enabled", false); //  Disable "beacon" asynchronous HTTP transfers (used for analytics)
user_pref("media.webspeech.recognition.enable", false); //  Disable speech recognition
user_pref("device.sensors.enabled", false); //  Disable sensor API
user_pref("browser.send_pings", false); //  Disable pinging URIs specified in HTML <a> ping= attributes
user_pref("browser.send_pings.require_same_host", true); //  When browser pings are enabled, only allow pinging the same host as the origin page
user_pref("camera.control.face_detection.enabled", false); //  Disable face detection
user_pref("clipboard.autocopy", false); //  Do not automatically send selection to clipboard on some Linux platforms
user_pref("javascript.use_us_english_locale", true); //  Prevent leaking application locale/date format using JavaScript
user_pref("keyword.enabled", false); // Search by addressbar - Do not submit invalid URIs entered in the address bar to the default search engine - 
user_pref("network.manage-offline-status", false); //  Don't monitor OS online/offline connection state
user_pref("media.video_stats.enabled", false); //  Disable video stats to reduce fingerprinting threat
user_pref("browser.casting.enabled", false); //  Disable SSDP
user_pref("browser.aboutHomeSnippets.updateUrl", ""); //  Disable downloading homepage snippets/messages from Mozilla
user_pref("browser.search.update", false); //  Never check updates for search engines
user_pref("browser.topsites.contile.enabled", false); //  Disable (parts of?) "TopSites"
user_pref("network.negotiate-auth.allow-insecure-ntlm-v1", false); //  Disallow NTLMv1
user_pref("browser.chrome.site_icons", false); //  Disable downloading of favicons in response to favicon fingerprinting techniques

/*** STARTUP ***/
user_pref("browser.startup.blankWindow", false); //  enable RFP letterboxing / resizing of inner window [FF67+] (disabled)
user_pref("browser.newtab.preload", false);
user_pref("browser.newtabpage.enhanced", false); //  Disable new tab tile ads & preload
user_pref("browser.newtabpage.activity-stream.enabled", false); //  Disable Activity Stream
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false); // [FF58+] Pocket > Sponsored Stories
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false); // [FF83+] Sponsored shortcuts
user_pref("browser.newtabpage.activity-stream.default.sites", "");
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false); //  Disable Snippets
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false); //  Disable "Recommended by Pocket" in Firefox Quantum
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr", false); //  Disable Extension recommendations (Firefox >= 65)
user_pref("browser.newtabpage.directory.ping", "");
user_pref("browser.newtabpage.directory.source", "data:text/plain,{}");

/*** GEOLOCATION ***/
user_pref("geo.enabled", false);
user_pref("geo.wifi.uri", "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%");
user_pref("geo.provider.network.url", "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%");
user_pref("geo.provider.ms-windows-location", false); // [WINDOWS]
user_pref("geo.provider.use_corelocation", false); // [MAC]
user_pref("geo.provider.use_gpsd", false); // [LINUX] [HIDDEN PREF]
user_pref("geo.provider.use_geoclue", false); // [FF102+] [LINUX]

/** RECOMMENDATIONS ***/
user_pref("extensions.getAddons.showPane", false); // [HIDDEN PREF]
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("browser.discovery.enabled", false);
user_pref("browser.shopping.experience2023.enabled", false); // [DEFAULT: false]

/** TELEMETRY ***/
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.enabled", false); // see [NOTE]
user_pref("toolkit.telemetry.server", "data:,");
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false); // [FF55+]
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false); // [FF55+]
user_pref("toolkit.telemetry.updatePing.enabled", false); // [FF56+]
user_pref("toolkit.telemetry.bhrPing.enabled", false); // [FF57+] Background Hang Reporter
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false); // [FF57+]
user_pref("toolkit.telemetry.coverage.opt-out", true); // [HIDDEN PREF]
user_pref("toolkit.coverage.opt-out", true); // [FF64+] [HIDDEN PREF]
user_pref("toolkit.coverage.endpoint.base", "");
user_pref("browser.ping-centre.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("experiments.supported", false);
user_pref("experiments.enabled", false);
user_pref("experiments.manifest.uri", "");
user_pref("network.allow-experiments", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("extensions.shield-recipe-client.enabled", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false); //  Disable collection/sending of the health report (healthreport.sqlite*)
user_pref("datareporting.healthreport.service.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.discovery.enabled", false);
user_pref("loop.logDomains", false); //  Disable Firefox Hello metrics collection

/** CRASH REPORTS ***/
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false); // [FF44+]
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false); // [DEFAULT: false]
user_pref("browser.crashReports.unsubmittedCheck.enabled", false);

/*** SAFE BROWSING (SB) ***/
user_pref("browser.safebrowsing.downloads.remote.enabled", false); //  Disable querying Google Application Reputation database for downloaded binary files
user_pref("browser.safebrowsing.phishing.enabled", true); //  Enable blocking reported web forgeries
user_pref("browser.safebrowsing.malware.enabled", true); //  Enable blocking reported attack sites
user_pref("browser.safebrowsing.blockedURIs.enabled", true); //  When Flash is enabled, download and use Mozilla SWF URIs blocklist

/*** BLOCK IMPLICIT OUTBOUND [not explicitly asked for - e.g. clicked on] ***/
user_pref("network.prefetch-next", false); //  Disable prefetching of <link rel="next"> URLs
user_pref("network.dns.disablePrefetch", true); //  Disable DNS prefetching
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.predictor.enabled", false); //  Disable the predictive service (Necko)
user_pref("network.dns.blockDotOnion", true); //  Reject .onion hostnames before passing the to DNS
user_pref("network.predictor.enable-prefetch", false); // [FF48+] [DEFAULT: false]
user_pref("network.http.speculative-parallel-limit", 0); //  Disable speculative pre-connections
user_pref("browser.places.speculativeConnect.enabled", false);

/*** DNS / DoH / PROXY / SOCKS ***/
user_pref("network.proxy.socks_remote_dns", true); //  Send DNS request through SOCKS when SOCKS proxying is in use
user_pref("network.file.disable_unc_paths", true); // [HIDDEN PREF]
user_pref("network.gio.supported-protocols", ""); // [HIDDEN PREF] [DEFAULT: "" FF118+]

/*** LOCATION BAR / SEARCH BAR / SUGGESTIONS / HISTORY / FORMS ***/ 
user_pref("browser.urlbar.trimURLs", false);//  Don't trim HTTP off of URLs in the address bar.
user_pref("browser.urlbar.speculativeConnect.enabled", false); //  Disable preloading of autocomplete URLs.
user_pref("browser.urlbar.groupLabels.enabled", false);
user_pref("browser.urlbar.suggest.searches", false); //  Disable "Show search suggestions in location bar results"
user_pref("browser.urlbar.suggest.quicksuggest.nonsponsored", false); // [FF95+]
user_pref("browser.urlbar.suggest.quicksuggest.sponsored", false); // [FF92+]
user_pref("browser.urlbar.trending.featureGate", false);
user_pref("browser.urlbar.addons.featureGate", false); // [FF115+]
user_pref("browser.urlbar.mdn.featureGate", false); // [FF117+] [HIDDEN PREF]
user_pref("browser.urlbar.pocket.featureGate", false); // [FF116+] [DEFAULT: false]
user_pref("browser.urlbar.weather.featureGate", false); // [FF108+] [DEFAULT: false]
user_pref("browser.formfill.enable", false); //  Disable form autofill, don't save information entered in web page forms and the Search Bar
user_pref("browser.formfill.expire_days", 0); //  Delete Search and Form History
user_pref("browser.search.suggest.enabled", false); //  Disable search suggestions in the search bar
user_pref("browser.search.separatePrivateDefault", true); // [FF70+]
user_pref("browser.search.separatePrivateDefault.ui.enabled", true); // [FF71+]
user_pref("browser.fixup.alternate.enabled", false); //  Don't try to guess domain names when entering an invalid domain name in URL bar
user_pref("browser.fixup.hide_user_pass", true); //  When browser.fixup.alternate.enabled is enabled, strip password from 'user:password@...' URLs

/*** PASSWORDS ***/
user_pref("signon.rememberSignons", false); //  Disable password manager (use an external password manager!)
user_pref("signon.autofillForms", false); //  Require manual intervention to autofill known username/passwords sign-in forms
user_pref("signon.autofillForms.http", false); //  When username/password autofill is enabled, still disable it on non-HTTPS sites
user_pref("signon.formlessCapture.enabled", false);
user_pref("network.auth.subresource-http-auth-allow", 1);

/** UI (User Interface) ***/
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true); //  Warn the user when server doesn't support RFC 5746 ("safe" renegotiation)
user_pref("browser.xul.error_pages.expert_bad_cert", true);

/*** CONTAINERS & PRIVACY ***/
user_pref("privacy.userContext.enabled", true); //  Enable contextual identity Containers feature (Firefox >= 52)
user_pref("privacy.userContext.ui.enabled", true);
user_pref("privacy.trackingprotection.enabled", true);//  Enable Firefox Tracking Protection
user_pref("privacy.trackingprotection.pbmode.enabled", true);
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true); //  disable mozAddonManager Web API [FF57+]

/*** PLUGINS / MEDIA / WEBRTC ***/
user_pref("media.peerconnection.ice.no_host", true); //  Don't reveal your internal IP when WebRTC is enabled (Firefox >= 42)
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
user_pref("media.peerconnection.ice.default_address_only", true);

/*** DOM (DOCUMENT OBJECT MODEL) ***/
user_pref("dom.disable_window_move_resize", true);

/*** MISCELLANEOUS ***/
user_pref("browser.download.start_downloads_in_tmp_dir", false); // [FF102+]
user_pref("browser.helperApps.deleteTempFileOnExit", true);
user_pref("browser.uitour.enabled", false); //  Disable the UITour backend
user_pref("devtools.debugger.remote-enabled", false); //  Disable remote debugging
user_pref("devtools.chrome.enabled", false);
user_pref("devtools.debugger.force-local", true);
user_pref("permissions.manager.defaultsUrl", "");
user_pref("webchannel.allowObject.urlWhitelist", "");
user_pref("network.IDN_show_punycode", true); //  Force Punycode for Internationalized Domain Names
user_pref("browser.shell.checkDefaultBrowser", false); //  Do not check if Firefox is the default browser
user_pref("pdfjs.disabled", true); //  Disable the built-in PDF viewer
user_pref("pdfjs.enableScripting", false); // [FF86+]
user_pref("browser.tabs.searchclipboardfor.middleclick", false); // [DEFAULT: false NON-LINUX]

/** DOWNLOADS ***/
user_pref("browser.download.useDownloadDir", false); //  Always ask the user where to download
user_pref("browser.download.alwaysOpenPanel", false);
user_pref("browser.download.manager.addToRecentDocs", false);

/** EXTENSIONS ***/
user_pref("extensions.enabledScopes", 5); // [HIDDEN PREF] limit allowed extension directories: 1=profile, 2=user, 4=application, 8=system, 16=temporary, 31=all 
user_pref("extensions.postDownloadThirdPartyPrompt", false);
user_pref("extensions.getAddons.cache.enabled", false); //  Opt-out of add-on metadata updates
user_pref("lightweightThemes.update.enabled", false); //  Opt-out of themes (Persona) updates
user_pref("extensions.update.enabled", true); //  Updates addons automatically
user_pref("extensions.blocklist.enabled", true); //  Enable add-on and certificate blocklists (OneCRL) from Mozilla
user_pref("services.blocklist.update_enabled", true); 
user_pref("extensions.blocklist.url", "https://blocklist.addons.mozilla.org/blocklist/3/%APP_ID%/%APP_VERSION%/"); //  Decrease system information leakage to Mozilla blocklist update servers
user_pref("extensions.systemAddon.update.enabled", false); //  Disable system add-on updates (hidden & always-enabled add-ons from Mozilla)
user_pref("extensions.webextensions.restrictedDomains", "");

/** MIXED CONTENT ***/
user_pref("dom.security.https_only_mode", true); // [FF76+]
user_pref("dom.security.https_only_mode_send_http_background_request", false);

/*** SECURITY ***/
user_pref("security.dialog_enable_delay", 1000); //  Ensure you have a security delay when installing add-ons (milliseconds)
user_pref("security.csp.experimentalEnabled", true); //  Enable CSP 1.1 script-nonce directive support
user_pref("security.csp.enable", true); //  Enable Content Security Policy (CSP)
user_pref("security.sri.enable", true); //  Enable Subresource Integrity
user_pref("security.insecure_field_warning.contextual.enabled", true); //  Show in-content login form warning UI for insecure login fields
user_pref("security.insecure_password.ui.enabled", true); //  Enable insecure password warnings (login forms in non-HTTPS pages)
user_pref("security.ssl.errorReporting.automatic", false); //  Disable automatic reporting of TLS connection errors
user_pref("browser.ssl_override_behavior", 1); //  Pre-populate the current URL but do not pre-fetch the certificate in the "Add Security Exception" dialog
user_pref("network.security.esni.enabled", true); //  Encrypted SNI (when TRR is enabled)

/*** SSL (Secure Sockets Layer) / TLS (Transport Layer Security) ***/
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.tls.enable_0rtt_data", false);
//  Only allow TLS 1.[2-3]
// http://kb.mozillazine.org/Security.tls.version.*
// 1 = TLS 1.0 is the minimum required / maximum supported encryption protocol. (This is the current default for the maximum supported version.)
// 2 = TLS 1.1 is the minimum required / maximum supported encryption protocol.
// 3 = TLS 1.2 is the minimum required / maximum supported encryption protocol.
// 4 = TLS 1.3 is the minimum required / maximum supported encryption protocol.
user_pref("security.tls.version.min", 3);
user_pref("security.tls.version.max", 4);
user_pref("security.tls.version.fallback-limit", 4); //  Disable insecure TLS version fallback
user_pref("network.stricttransportsecurity.preloadlist", true); //  Enable HSTS preload list (pre-set HSTS sites list provided by Mozilla)
user_pref("security.ssl.disable_session_identifiers", true); //  Disable TLS Session Tickets

/*** OCSP (Online Certificate Status Protocol) ***/
user_pref("security.OCSP.enabled", 1); // [DEFAULT: 1]
user_pref("security.OCSP.require", true);
user_pref("security.ssl.enable_ocsp_stapling", true); //  Enable Online Certificate Status Protocol
user_pref("security.ssl.enable_ocsp_must_staple", true); //  Enable OCSP Must-Staple support (Firefox >= 45)

/** CERTS / HPKP (HTTP Public Key Pinning) ***/
user_pref("security.cert_pinning.enforcement_level", 2); //  Enforce Public Key Pinning
user_pref("security.remote_settings.crlite_filters.enabled", true);
user_pref("security.pki.crlite_mode", 2);

/*** Ciphers ***/
user_pref("security.pki.sha1_enforcement_level", 1); //  Disallow SHA-1
user_pref("security.ssl3.rsa_null_sha",  false); //  Disable null ciphers
user_pref("security.ssl3.rsa_null_md5",  false);
user_pref("security.ssl3.ecdhe_rsa_null_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_null_sha", false);
user_pref("security.ssl3.ecdh_rsa_null_sha", false);
user_pref("security.ssl3.ecdh_ecdsa_null_sha", false);
user_pref("security.ssl3.rsa_seed_sha",  false); //  Disable SEED cipher
user_pref("security.ssl3.rsa_rc4_40_md5", false); //  Disable 40/56/128-bit ciphers
user_pref("security.ssl3.rsa_rc2_40_md5", false);
user_pref("security.ssl3.rsa_1024_rc4_56_sha", false);
user_pref("security.ssl3.rsa_camellia_128_sha", false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha", false);
user_pref("security.ssl3.ecdh_rsa_aes_128_sha", false);
user_pref("security.ssl3.ecdh_ecdsa_aes_128_sha", false);
user_pref("security.ssl3.dhe_rsa_camellia_128_sha", false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.ecdh_ecdsa_rc4_128_sha", false); //  Disable RC4
user_pref("security.ssl3.ecdh_rsa_rc4_128_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha", false);
user_pref("security.ssl3.ecdhe_rsa_rc4_128_sha", false);
user_pref("security.ssl3.rsa_rc4_128_md5", false);
user_pref("security.ssl3.rsa_rc4_128_sha", false);
user_pref("security.tls.unrestricted_rc4_fallback", false);
user_pref("security.ssl3.dhe_dss_des_ede3_sha", false); //  Disable 3DES (effective key size is < 128)
user_pref("security.ssl3.dhe_rsa_des_ede3_sha", false);
user_pref("security.ssl3.ecdh_ecdsa_des_ede3_sha", false);
user_pref("security.ssl3.ecdh_rsa_des_ede3_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_des_ede3_sha", false);
user_pref("security.ssl3.ecdhe_rsa_des_ede3_sha", false);
user_pref("security.ssl3.rsa_des_ede3_sha", false);
user_pref("security.ssl3.rsa_fips_des_ede3_sha", false);
user_pref("security.ssl3.ecdh_rsa_aes_256_sha", false); //  Disable ciphers with ECDH (non-ephemeral)
user_pref("security.ssl3.ecdh_ecdsa_aes_256_sha", false);
user_pref("security.ssl3.rsa_camellia_256_sha", false); //  Disable 256 bits ciphers without PFS
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256", true); //  Enable GCM ciphers (TLSv1.2 only)
user_pref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256", true);
user_pref("security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256", true); //  Enable ChaCha20 and Poly1305 (Firefox >= 47)
user_pref("security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256", true);
user_pref("security.ssl3.dhe_rsa_camellia_256_sha", false); //  Disable ciphers susceptible to the logjam attack
user_pref("security.ssl3.dhe_rsa_aes_256_sha", false);
user_pref("security.ssl3.dhe_dss_aes_128_sha", false); //  Disable ciphers with DSA (max 1024 bits)
user_pref("security.ssl3.dhe_dss_aes_256_sha", false);
user_pref("security.ssl3.dhe_dss_camellia_128_sha", false);
user_pref("security.ssl3.dhe_dss_camellia_256_sha", false);
user_pref("security.tls.enable_kyber",  true); //  Enable X25519Kyber768Draft00 (post-quantum key exchange) [FF Nightly 2024-01-18+]

/** OTHER ***/
user_pref("network.connectivity-service.enabled", false);