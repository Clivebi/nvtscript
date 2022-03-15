if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71480" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-2417" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2012-08-10 03:07:10 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2502-1 (python-crypto)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202502-1" );
	script_tag( name: "insight", value: "It was discovered that the ElGamal code in PythonCrypto, a
collection of cryptographic algorithms and protocols for Python used
insecure insufficient prime numbers in key generation, which lead to a
weakened signature or public key space, allowing easier brute force
attacks on such keys.

For the stable distribution (squeeze), this problem has been fixed in
version 2.1.0-2+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 2.6-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your python-crypto packages. After" );
	script_tag( name: "summary", value: "The remote host is missing an update to python-crypto
announced via advisory DSA 2502-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-crypto", ver: "2.1.0-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-crypto-dbg", ver: "2.1.0-2+squeeze1", rls: "DEB6" ) ) != NULL){
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

