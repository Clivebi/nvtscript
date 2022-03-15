if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702917" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0470" );
	script_name( "Debian Security Advisory DSA 2917-1 (super - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-28 00:00:00 +0200 (Mon, 28 Apr 2014)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2917.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "super on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 3.30.0-3+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 3.30.0-6+deb7u1.

We recommend that you upgrade your super packages." );
	script_tag( name: "summary", value: "John Lightsey of the Debian Security Audit project discovered that the
super package did not check for setuid failures, allowing local users
to increase the privileges on kernel versions which do not guard
against RLIMIT_NPROC attacks." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "super", ver: "3.30.0-3+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "super", ver: "3.30.0-6+deb7u1", rls: "DEB7" ) ) != NULL){
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

