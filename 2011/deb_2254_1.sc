if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69961" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-1760" );
	script_name( "Debian Security Advisory DSA 2254-1 (oprofile)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202254-1" );
	script_tag( name: "insight", value: "OProfile is a performance profiling tool which is configurable by opcontrol, its
control utility. Stephane Chauveau reported several ways to inject arbitrary
commands in the arguments of this utility. If a local unprivileged user is
authorized by sudoers file to run opcontrol as root, this user could use the
flaw to escalate his privileges.


For the oldstable distribution (lenny), this problem has been fixed in
version 0.9.3-2+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 0.9.6-1.1+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 0.9.6-1.2.

For the unstable distribution (sid), this problem has been fixed in
version 0.9.6-1.2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your oprofile packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to oprofile
announced via advisory DSA 2254-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "oprofile", ver: "0.9.3-2+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "oprofile-gui", ver: "0.9.3-2+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "oprofile", ver: "0.9.6-1.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "oprofile-gui", ver: "0.9.6-1.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "oprofile", ver: "0.9.6-1.2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "oprofile-gui", ver: "0.9.6-1.2", rls: "DEB7" ) ) != NULL){
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

