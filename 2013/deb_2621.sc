if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702621" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-0169", "CVE-2013-0166" );
	script_name( "Debian Security Advisory DSA 2621-1 (openssl - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-02-13 00:00:00 +0100 (Wed, 13 Feb 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2621.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "openssl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), these problems have been fixed in
version 0.9.8o-4squeeze14.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.1e-1.

We recommend that you upgrade your openssl packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been found in OpenSSL. The Common
Vulnerabilities and Exposures project identifies the following issues:

CVE-2013-0166
OpenSSL does not properly perform signature verification for OCSP
responses, which allows remote attackers to cause a denial of
service via an invalid key.

CVE-2013-0169A timing side channel attack has been found in CBC padding
allowing an attacker to recover pieces of plaintext via statistical
analysis of crafted packages, known as the Lucky Thirteen
issue." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libcrypto0.9.8-udeb", ver: "0.9.8o-4squeeze14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "0.9.8o-4squeeze14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8", ver: "0.9.8o-4squeeze14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8-dbg", ver: "0.9.8o-4squeeze14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "0.9.8o-4squeeze14", rls: "DEB6" ) ) != NULL){
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
