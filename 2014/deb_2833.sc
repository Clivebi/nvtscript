if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702833" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2013-6449", "CVE-2013-6450" );
	script_name( "Debian Security Advisory DSA 2833-1 (openssl - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-01 00:00:00 +0100 (Wed, 01 Jan 2014)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2833.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "openssl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 1.0.1e-2+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.1e-5.

We recommend that you upgrade your openssl packages." );
	script_tag( name: "summary", value: "Multiple security issues have been fixed in OpenSSL: The TLS 1.2 support
was susceptible to denial of service and retransmission of DTLS messages
was fixed. In addition this update disables the insecure Dual_EC_DRBG
algorithm and no longer uses the RdRand feature available on some
Intel CPUs as a sole source of entropy unless explicitly requested." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.0.1e-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.0.1e-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1e-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0-dbg", ver: "1.0.1e-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "1.0.1e-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

