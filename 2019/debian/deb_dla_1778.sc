if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891778" );
	script_version( "2021-10-04T08:02:33+0000" );
	script_cve_id( "CVE-2019-10909", "CVE-2019-10910", "CVE-2019-10911", "CVE-2019-10913" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-04 08:02:33 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-29 16:23:00 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:00:10 +0000 (Tue, 07 May 2019)" );
	script_name( "Debian LTS: Security Advisory for symfony (DLA-1778-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1778-1" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2019-10909-escape-validation-messages-in-the-php-templating-engine" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2019-10910-check-service-ids-are-valid" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2019-10911-add-a-separator-in-the-remember-me-cookie-hash" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2019-10913-reject-invalid-http-method-overrides" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'symfony'
  package(s) announced via the DLA-1778-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security vulnerabilities have been discovered in symfony, a PHP
web application framework. Numerous symfony components are affected:
Framework Bundle, Dependency Injection, Security, HttpFoundation

CVE-2019-10909

Validation messages were not escaped when using the form theme of
the PHP templating engine which, when validation messages may
contain user input, could result in an XSS.

CVE-2019-10910

Service IDs derived from unfiltered user input could result in the
execution of any arbitrary code, resulting in possible remote code
execution.

CVE-2019-10911

This fixes situations where part of an expiry time in a cookie could
be considered part of the username, or part of the username could be
considered part of the expiry time. An attacker could modify the
remember me cookie and authenticate as a different user. This attack
is only possible if remember me functionality is enabled and the two
users share a password hash or the password hashes (e.g.
UserInterface::getPassword()) are null for all users (which is valid
if passwords are checked by an external system, e.g. an SSO).

CVE-2019-10913

HTTP methods, from either the HTTP method itself or using the
X-Http-Method-Override header were previously returned as the method
in question without validation being done on the string, meaning
that they could be used in dangerous contexts when left unescaped." );
	script_tag( name: "affected", value: "'symfony' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.3.21+dfsg-4+deb8u5.

We recommend that you upgrade your symfony packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-browser-kit", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-class-loader", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-classloader", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-config", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-console", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-css-selector", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-debug", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-dependency-injection", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-doctrine-bridge", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-dom-crawler", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-event-dispatcher", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-eventdispatcher", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-filesystem", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-finder", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-form", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-framework-bundle", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-http-foundation", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-http-kernel", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-intl", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-locale", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-monolog-bridge", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-options-resolver", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-process", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-propel1-bridge", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-property-access", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-proxy-manager-bridge", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-routing", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-security", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-security-bundle", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-serializer", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-stopwatch", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-swiftmailer-bridge", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-templating", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-translation", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-twig-bridge", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-twig-bundle", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-validator", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-web-profiler-bundle", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-yaml", ver: "2.3.21+dfsg-4+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}
exit( 0 );

