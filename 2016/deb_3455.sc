if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703455" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_cve_id( "CVE-2016-0755" );
	script_name( "Debian Security Advisory DSA 3455-1 (curl - security update)" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-01-27 00:00:00 +0100 (Wed, 27 Jan 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-17 01:29:00 +0000 (Wed, 17 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3455.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "curl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 7.38.0-4+deb8u3.

For the unstable distribution (sid), this problem has been fixed in
version 7.47.0-1.

We recommend that you upgrade your curl packages." );
	script_tag( name: "summary", value: "Isaac Boukris discovered that cURL,
an URL transfer library, reused NTLM-authenticated proxy connections without
properly making sure that the connection was authenticated with the same
credentials as set for the new transfer. This could lead to HTTP requests
being sent over the connection authenticated as a different user." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "curl", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3:amd64", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3:i386", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-dbg:amd64", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-dbg:i386", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-gnutls:amd64", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-gnutls:i386", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-nss:amd64", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-nss:i386", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-doc", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev:amd64", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev:i386", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.38.0-4+deb8u3", rls: "DEB8" ) ) != NULL){
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

