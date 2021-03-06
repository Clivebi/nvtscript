if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703649" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-6313" );
	script_name( "Debian Security Advisory DSA 3649-1 (gnupg - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-17 00:00:00 +0200 (Wed, 17 Aug 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3649.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "gnupg on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1.4.18-7+deb8u2.

We recommend that you upgrade your gnupg packages." );
	script_tag( name: "summary", value: "Felix Doerre and Vladimir Klebanov from
the Karlsruhe Institute of Technology discovered a flaw in the mixing functions of
GnuPG's random number generator. An attacker who obtains 4640 bits from the RNG can
trivially predict the next 160 bits of output.

A first analysis on the impact of this bug for GnuPG shows that existing
RSA keys are not weakened. For DSA and Elgamal keys it is also unlikely
that the private key can be predicted from other public information." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gnupg", ver: "1.4.18-7+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnupg-curl", ver: "1.4.18-7+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gpgv", ver: "1.4.18-7+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gpgv-win32", ver: "1.4.18-7+deb8u2", rls: "DEB8" ) ) != NULL){
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

