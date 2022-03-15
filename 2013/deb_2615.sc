if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702615" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-5964", "CVE-2012-5962", "CVE-2012-5961", "CVE-2012-5959", "CVE-2012-5965", "CVE-2012-5963", "CVE-2012-5960", "CVE-2012-5958" );
	script_name( "Debian Security Advisory DSA 2615-1 (libupnp4 - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-02-01 00:00:00 +0100 (Fri, 01 Feb 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2615.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "libupnp4 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), these problems have been fixed in
version 1.8.0~svn20100507-1+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in
version 1.8.0~svn20100507-1.2.

For the unstable distribution (sid), these problems have been fixed in
version 1.8.0~svn20100507-1.2.

We recommend that you upgrade your libupnp4 packages." );
	script_tag( name: "summary", value: "Multiple stack-based buffer overflows were discovered in libupnp4, a library
used for handling the Universal Plug and Play protocol. HD Moore from Rapid7
discovered that SSDP queries where not correctly handled by the
unique_service_name() function.

An attacker sending carefully crafted SSDP queries to a daemon built on
libupnp4 could generate a buffer overflow, overwriting the stack, leading to
the daemon crash and possible remote code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libupnp4", ver: "1.8.0~svn20100507-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libupnp4-dbg", ver: "1.8.0~svn20100507-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libupnp4-dev", ver: "1.8.0~svn20100507-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libupnp4-doc", ver: "1.8.0~svn20100507-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libupnp4", ver: "1.8.0~svn20100507-1.2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libupnp4-dbg", ver: "1.8.0~svn20100507-1.2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libupnp4-dev", ver: "1.8.0~svn20100507-1.2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libupnp4-doc", ver: "1.8.0~svn20100507-1.2", rls: "DEB7" ) ) != NULL){
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

