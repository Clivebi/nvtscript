if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703296" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-2141" );
	script_name( "Debian Security Advisory DSA 3296-1 (libcrypto++ - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-29 00:00:00 +0200 (Mon, 29 Jun 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3296.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libcrypto++ on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 5.6.1-6+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 5.6.1-6+deb8u1.

For the testing distribution (stretch), this problem will be fixed
in version 5.6.1-7.

For the unstable distribution (sid), this problem has been fixed in
version 5.6.1-7.

We recommend that you upgrade your libcrypto++ packages." );
	script_tag( name: "summary", value: "Evgeny Sidorov discovered that
libcrypto++, a general purpose C++ cryptographic library, did not properly
implement blinding to mask private key operations for the Rabin-Williams
digital signature algorithm. This could allow remote attackers to mount a
timing attack and retrieve the user's private key." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libcrypto++-dev", ver: "5.6.1-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcrypto++-doc", ver: "5.6.1-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcrypto++-utils", ver: "5.6.1-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcrypto++9", ver: "5.6.1-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcrypto++9-dbg", ver: "5.6.1-6+deb7u1", rls: "DEB7" ) ) != NULL){
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

