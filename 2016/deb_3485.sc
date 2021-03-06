if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703485" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2013-7448" );
	script_name( "Debian Security Advisory DSA 3485-1 (didiwiki - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-02-20 00:00:00 +0100 (Sat, 20 Feb 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3485.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|9|8)" );
	script_tag( name: "affected", value: "didiwiki on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 0.5-11+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 0.5-11+deb8u1.

For the testing (stretch) and unstable (sid) distributions, this
problem has been fixed in version 0.5-12.

We recommend that you upgrade your didiwiki packages." );
	script_tag( name: "summary", value: "Alexander Izmailov discovered that
didiwiki, a wiki implementation, failed to correctly validate user-supplied
input, thus allowing a malicious user to access any part of the filesystem." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "didiwiki", ver: "0.5-11+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "didiwiki", ver: "0.5-12", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "didiwiki", ver: "0.5-11+deb8u1", rls: "DEB8" ) ) != NULL){
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

