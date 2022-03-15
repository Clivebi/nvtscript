if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69559" );
	script_cve_id( "CVE-2011-1572" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Debian Security Advisory DSA 2215-1 (gitolite)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202215-1" );
	script_tag( name: "insight", value: "Dylan Simon discovered that gitolite, a SSH-based gatekeeper for git
repositories, is prone to directory traversal attacks when restricting
admin defined commands (ADC).  This allows an attacker to execute arbitrary
commands with privileges of the gitolite server via crafted command names.

Please note that this only affects installations that have ADC enabled
(not the Debian default).


The oldstable distribution (lenny) is not affected by this problem,
it does not include gitolite.

For the stable distribution (squeeze), this problem has been fixed in
version 1.5.4-2+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 1.5.7-2.

For the unstable distribution (sid), this problem has been fixed in
version 1.5.7-2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your gitolite packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to gitolite
announced via advisory DSA 2215-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gitolite", ver: "1.5.4-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gitolite", ver: "1.5.7-2", rls: "DEB7" ) ) != NULL){
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

