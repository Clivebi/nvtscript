if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69117" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-0715" );
	script_name( "Debian Security Advisory DSA 2182-1 (logwatch)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_tag( name: "insight", value: "Dominik George discovered that logwatch does not guard against shell
meta-characters in crafted log file names (such as those produced by
Samba).  As a result, an attacker might be able to execute shell
commands on the system running logwatch." );
	script_tag( name: "summary", value: "The remote host is missing an update to logwatch
announced via advisory DSA 2182-1." );
	script_tag( name: "solution", value: "For the oldstable distribution (lenny), this problem has been fixed in
version 7.3.6.cvs20080702-2lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 7.3.6.cvs20090906-1squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 7.3.6.cvs20090906-2.

We recommend that you upgrade your logwatch packages." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202182-1" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "logwatch", ver: "7.3.6.cvs20080702-2lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "logwatch", ver: "7.3.6.cvs20090906-1squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "logwatch", ver: "7.3.6.cvs20090906-2", rls: "DEB7" ) ) != NULL){
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

