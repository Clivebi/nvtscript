if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702731" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4242" );
	script_name( "Debian Security Advisory DSA 2731-1 (libgcrypt11 - information leak)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-29 00:00:00 +0200 (Mon, 29 Jul 2013)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2731.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "libgcrypt11 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.4.5-2+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 1.5.0-5+deb7u1.

For the testing distribution (jessie) and unstable distribution (sid),
this problem has been fixed in version 1.5.3-1.

We recommend that you upgrade your libgcrypt11 packages." );
	script_tag( name: "summary", value: "Yarom and Falkner discovered that RSA secret keys in applications using
the libgcrypt11 library, for example GnuPG 2.x, could be leaked via
a side channel attack, where a malicious local user could obtain private
key information from another user on the system." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libgcrypt11", ver: "1.4.5-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11-dbg", ver: "1.4.5-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11-dev", ver: "1.4.5-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11-doc", ver: "1.4.5-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11", ver: "1.5.0-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11-dbg", ver: "1.5.0-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11-dev", ver: "1.5.0-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11-doc", ver: "1.5.0-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11-udeb", ver: "1.5.0-5+deb7u1", rls: "DEB7" ) ) != NULL){
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

