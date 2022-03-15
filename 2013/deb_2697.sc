if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702697" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-2116" );
	script_name( "Debian Security Advisory DSA 2697-1 (gnutls26 - out-of-bounds array read)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-05-29 00:00:00 +0200 (Wed, 29 May 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2697.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "gnutls26 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 2.12.20-7.

For the unstable distribution (sid), this problem has been fixed in
version 2.12.23-5.

We recommend that you upgrade your gnutls26 packages." );
	script_tag( name: "summary", value: "It was discovered that a malicious client could crash a GNUTLS server
and vice versa, by sending TLS records encrypted with a block cipher
which contain invalid padding.

The oldstable distribution (squeeze) is not affected because the
security fix that introduced this vulnerability was not applied to it." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gnutls-bin", ver: "2.12.20-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnutls26-doc", ver: "2.12.20-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "guile-gnutls", ver: "2.12.20-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgnutls-dev", ver: "2.12.20-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgnutls-openssl27", ver: "2.12.20-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgnutls26", ver: "2.12.20-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgnutls26-dbg", ver: "2.12.20-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgnutlsxx27", ver: "2.12.20-7", rls: "DEB7" ) ) != NULL){
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

