if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702763" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4314" );
	script_name( "Debian Security Advisory DSA 2763-1 (pyopenssl - hostname check bypassing)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-24 00:00:00 +0200 (Tue, 24 Sep 2013)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2763.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "pyopenssl on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 0.10-1+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 0.13-2+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 0.13-2.1.

We recommend that you upgrade your pyopenssl packages." );
	script_tag( name: "summary", value: "It was discovered that PyOpenSSL, a Python wrapper around the OpenSSL
library, does not properly handle certificates with NULL characters in
the Subject Alternative Name field." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-openssl", ver: "0.10-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-openssl-dbg", ver: "0.10-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-openssl-doc", ver: "0.10-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-openssl", ver: "0.13-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-openssl-dbg", ver: "0.13-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-openssl-doc", ver: "0.13-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-openssl", ver: "0.13-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-openssl-dbg", ver: "0.13-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

