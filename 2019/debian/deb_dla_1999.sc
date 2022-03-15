if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891999" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-18886", "CVE-2019-18887", "CVE-2019-18888" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-26 12:50:05 +0000 (Tue, 26 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for symfony (DLA-1999-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00019.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1999-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'symfony'
  package(s) announced via the DLA-1999-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in the Symfony PHP framework
which could lead to a timing attack/information leak, argument injection
and code execution via unserialization." );
	script_tag( name: "affected", value: "'symfony' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.3.21+dfsg-4+deb8u6.

We recommend that you upgrade your symfony packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-browser-kit", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-class-loader", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-classloader", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-config", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-console", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-css-selector", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-debug", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-dependency-injection", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-doctrine-bridge", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-dom-crawler", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-event-dispatcher", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-eventdispatcher", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-filesystem", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-finder", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-form", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-framework-bundle", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-http-foundation", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-http-kernel", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-intl", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-locale", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-monolog-bridge", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-options-resolver", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-process", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-propel1-bridge", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-property-access", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-proxy-manager-bridge", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-routing", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-security", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-security-bundle", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-serializer", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-stopwatch", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-swiftmailer-bridge", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-templating", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-translation", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-twig-bridge", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-twig-bundle", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-validator", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-web-profiler-bundle", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-symfony-yaml", ver: "2.3.21+dfsg-4+deb8u6", rls: "DEB8" ) )){
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

