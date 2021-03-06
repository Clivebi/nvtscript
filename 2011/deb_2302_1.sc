if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70238" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-3211" );
	script_name( "Debian Security Advisory DSA 2302-1 (bcfg2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202302-1" );
	script_tag( name: "insight", value: "It has been discovered that the bcfg2 server, a configuration management
server for bcfg2 clients, is not properly sanitizing input from bcfg2
clients before passing it to various shell commands.  This enables an
attacker in control of a bcfg2 client to execute arbitrary commands on
the server with root privileges.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.9.5.7-1.1+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 1.0.1-3+squeeze1

For the testing distribution (wheezy), this problem has been fixed in
version 1.1.2-2.

For the unstable distribution (sid), this problem has been fixed in
version 1.1.2-2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your bcfg2 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to bcfg2
announced via advisory DSA 2302-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bcfg2", ver: "0.9.5.7-1.1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bcfg2-server", ver: "0.9.5.7-1.1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bcfg2", ver: "1.0.1-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bcfg2-server", ver: "1.0.1-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bcfg2", ver: "1.1.2-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bcfg2-server", ver: "1.1.2-2", rls: "DEB7" ) ) != NULL){
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

