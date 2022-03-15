if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703681" );
	script_version( "2021-09-20T14:01:48+0000" );
	script_cve_id( "CVE-2016-4029", "CVE-2016-6634", "CVE-2016-6635", "CVE-2016-7168", "CVE-2016-7169" );
	script_name( "Debian Security Advisory DSA 3681-1 (wordpress - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-10-05 15:43:20 +0530 (Wed, 05 Oct 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3681.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 4.1+dfsg-1+deb8u10.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in wordpress, a web blogging tool, which could allow remote attackers to compromise
a site via cross-site scripting, cross-site request forgery, path traversal, or
bypass restrictions." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "wordpress", ver: "4.1+dfsg-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.1+dfsg-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.1+dfsg-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentyfourteen", ver: "4.1+dfsg-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-theme-twentythirteen", ver: "4.1+dfsg-1+deb8u10", rls: "DEB8" ) ) != NULL){
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

