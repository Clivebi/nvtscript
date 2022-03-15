if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71354" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-2369" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:51:37 -0400 (Thu, 31 May 2012)" );
	script_name( "Debian Security Advisory DSA 2476-1 (pidgin-otr)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202476-1" );
	script_tag( name: "insight", value: "intrigeri discovered a format string error in pidgin-otr, an off-the-record
messaging plugin for Pidgin.

This could be exploited by a remote attacker to cause arbitrary code to
be executed on the user's machine.

The problem is only in pidgin-otr. Other applications which use libotr are
not affected.

For the stable distribution (squeeze), this problem has been fixed in
version 3.2.0-5+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 3.2.1-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.2.1-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your pidgin-otr packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to pidgin-otr
announced via advisory DSA 2476-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "pidgin-otr", ver: "3.2.0-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pidgin-otr", ver: "3.2.1-1", rls: "DEB7" ) ) != NULL){
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

