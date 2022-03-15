if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703779" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2017-5488", "CVE-2017-5489", "CVE-2017-5490", "CVE-2017-5491", "CVE-2017-5492", "CVE-2017-5493", "CVE-2017-5610", "CVE-2017-5611", "CVE-2017-5612" );
	script_name( "Debian Security Advisory DSA 3779-1 (wordpress - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-03 12:11:20 +0530 (Fri, 03 Feb 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-30 02:37:00 +0000 (Sat, 30 Jan 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3779.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 4.1+dfsg-1+deb8u12.

For the testing (stretch) and unstable (sid) distributions, these problems have
been fixed in version 4.7.1+dfsg-1.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in wordpress, a web blogging tool. They would allow remote attackers to hijack
victims' credentials, access sensitive information, execute arbitrary commands,
bypass read and post restrictions, or mount denial-of-service attacks." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "wordpress", ver: "4.7.1+dfsg-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.7.1+dfsg-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.7.1+dfsg-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentyseventeen", ver: "4.7.1+dfsg-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentysixteen", ver: "4.7.1+dfsg-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress", ver: "4.1+dfsg-1+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.1+dfsg-1+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.1+dfsg-1+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentyfourteen", ver: "4.1+dfsg-1+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentythirteen", ver: "4.1+dfsg-1+deb8u12", rls: "DEB8" ) ) != NULL){
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

