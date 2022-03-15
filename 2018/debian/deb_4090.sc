if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704090" );
	script_version( "2021-06-18T11:51:03+0000" );
	script_cve_id( "CVE-2017-16510", "CVE-2017-17091", "CVE-2017-17092", "CVE-2017-17093", "CVE-2017-17094", "CVE-2017-9066" );
	script_name( "Debian Security Advisory DSA 4090-1 (wordpress - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-04 02:29:00 +0000 (Sun, 04 Feb 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4090.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 4.1+dfsg-1+deb8u16.

For the stable distribution (stretch), these problems have been fixed in
version 4.7.5+dfsg-2+deb9u2.

We recommend that you upgrade your wordpress packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/wordpress" );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in Wordpress, a web blogging
tool. They allowed remote attackers to perform SQL injections and
various Cross-Side Scripting (XSS) and Server-Side Request Forgery
(SSRF) attacks, as well as bypass some access restrictions." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "4.1+dfsg-1+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.1+dfsg-1+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.1+dfsg-1+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfourteen", ver: "4.1+dfsg-1+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentythirteen", ver: "4.1+dfsg-1+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "4.7.5+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.7.5+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.7.5+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyseventeen", ver: "4.7.5+dfsg-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentysixteen", ver: "4.7.5+dfsg-2+deb9u2", rls: "DEB9" ) )){
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

