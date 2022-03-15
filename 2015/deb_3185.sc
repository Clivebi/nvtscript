if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703185" );
	script_version( "2019-12-18T09:57:42+0000" );
	script_cve_id( "CVE-2014-3591", "CVE-2015-0837" );
	script_name( "Debian Security Advisory DSA 3185-1 (libgcrypt11 - security update)" );
	script_tag( name: "last_modification", value: "2019-12-18 09:57:42 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-03-12 00:00:00 +0100 (Thu, 12 Mar 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3185.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libgcrypt11 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 1.5.0-5+deb7u3.

We recommend that you upgrade your libgcrypt11 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered
in libgcrypt:

CVE-2014-3591
The Elgamal decryption routine was susceptible to a side-channel
attack discovered by researchers of Tel Aviv University. Ciphertext
blinding was enabled to counteract it. Note that this may have a
quite noticeable impact on Elgamal decryption performance.

CVE-2015-0837
The modular exponentiation routine mpi_powm() was susceptible to a
side-channel attack caused by data-dependent timing variations when
accessing its internal pre-computed table." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libgcrypt11:amd64", ver: "1.5.0-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11:i386", ver: "1.5.0-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11-dbg", ver: "1.5.0-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11-dev", ver: "1.5.0-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11-doc", ver: "1.5.0-5+deb7u3", rls: "DEB7" ) ) != NULL){
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

