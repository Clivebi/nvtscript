if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703079" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-3158" );
	script_name( "Debian Security Advisory DSA 3079-1 (ppp - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-11-28 00:00:00 +0100 (Fri, 28 Nov 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3079.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ppp on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this
problem has been fixed in version 2.4.5-5.1+deb7u1.

For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version 2.4.6-3.

We recommend that you upgrade your ppp packages." );
	script_tag( name: "summary", value: "A vulnerability was discovered in ppp,
an implementation of the Point-to-Point Protocol: an integer overflow in the routine
responsible for parsing user-supplied options potentially allows a local attacker
to gain root privileges." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ppp", ver: "2.4.5-5.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ppp-dev", ver: "2.4.5-5.1+deb7u1", rls: "DEB7" ) ) != NULL){
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
