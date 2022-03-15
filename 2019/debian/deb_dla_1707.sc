if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891707" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2017-16652", "CVE-2017-16654", "CVE-2018-11385", "CVE-2018-11408", "CVE-2018-14773", "CVE-2018-19789", "CVE-2018-19790" );
	script_name( "Debian LTS: Security Advisory for symfony (DLA-1707-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-11 00:00:00 +0100 (Mon, 11 Mar 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-12 14:36:00 +0000 (Tue, 12 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00009.html" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2017-16652-open-redirect-vulnerability-on-security-handlers" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2017-16654-intl-bundle-readers-breaking-out-of-paths" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2018-11385-session-fixation-issue-for-guard-authentication" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2018-11408-open-redirect-vulnerability-on-security-handlers" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-risky-http-headers" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2018-19789-disclosure-of-uploaded-files-full-path" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2018-19790-open-redirect-vulnerability-when-using-security-http" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "symfony on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.3.21+dfsg-4+deb8u4.

We recommend that you upgrade your symfony packages." );
	script_tag( name: "summary", value: "Several security vulnerabilities have been discovered in symfony, a PHP
web application framework.  Numerous symfony components are affected:
Security, bundle readers, session handling, SecurityBundle,
HttpFoundation, Form, and Security\\Http.

The referenced upstream advisories contain further details." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-browser-kit", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-class-loader", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-classloader", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-config", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-console", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-css-selector", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-debug", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-dependency-injection", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-doctrine-bridge", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-dom-crawler", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-event-dispatcher", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-eventdispatcher", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-filesystem", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-finder", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-form", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-framework-bundle", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-http-foundation", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-http-kernel", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-intl", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-locale", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-monolog-bridge", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-options-resolver", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-process", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-propel1-bridge", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-property-access", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-proxy-manager-bridge", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-routing", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-security", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-security-bundle", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-serializer", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-stopwatch", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-swiftmailer-bridge", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-templating", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-translation", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-twig-bridge", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-twig-bundle", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-validator", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-web-profiler-bundle", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-yaml", ver: "2.3.21+dfsg-4+deb8u4", rls: "DEB8" ) )){
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

