if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703879" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_cve_id( "CVE-2016-10324", "CVE-2016-10325", "CVE-2016-10326", "CVE-2017-7853" );
	script_name( "Debian Security Advisory DSA 3879-1 (libosip2 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-13 00:00:00 +0200 (Tue, 13 Jun 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3879.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "libosip2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 4.1.0-2+deb8u1.

For the upcoming stable distribution (stretch), these problems have been
fixed in version 4.1.0-2.1.

For the unstable distribution (sid), these problems have been fixed in
version 4.1.0-2.1.

We recommend that you upgrade your libosip2 packages." );
	script_tag( name: "summary", value: "Multiple security vulnerabilities have been found in oSIP, a library
implementing the Session Initiation Protocol, which might result in
denial of service through malformed SIP messages." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libosip2-11", ver: "4.1.0-2.1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libosip2-dev", ver: "4.1.0-2.1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libosip2-11", ver: "4.1.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libosip2-dev", ver: "4.1.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

