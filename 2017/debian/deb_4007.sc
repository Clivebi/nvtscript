if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704007" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-1000257" );
	script_name( "Debian Security Advisory DSA 4007-1 (curl - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-27 00:00:00 +0200 (Fri, 27 Oct 2017)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-13 11:29:00 +0000 (Tue, 13 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4007.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "curl on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 7.38.0-4+deb8u7.

For the stable distribution (stretch), this problem has been fixed in
version 7.52.1-5+deb9u2.

For the unstable distribution (sid), this problem has been fixed in
version 7.56.1-1.

We recommend that you upgrade your curl packages." );
	script_tag( name: "summary", value: "Brian Carpenter, Geeknik Labs and 0xd34db347 discovered that cURL, an URL
transfer library, incorrectly parsed an IMAP FETCH response with size 0,
leading to an out-of-bounds read." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "curl", ver: "7.38.0-4+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.38.0-4+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.38.0-4+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.38.0-4+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.38.0-4+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-doc", ver: "7.38.0-4+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.38.0-4+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.38.0-4+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.38.0-4+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "curl", ver: "7.52.1-5+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.52.1-5+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.52.1-5+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.52.1-5+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.52.1-5+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-doc", ver: "7.52.1-5+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.52.1-5+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.52.1-5+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.52.1-5+deb9u2", rls: "DEB9" ) ) != NULL){
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

