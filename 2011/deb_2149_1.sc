if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68987" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-4352" );
	script_name( "Debian Security Advisory DSA 2149-1 (dbus)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202149-1" );
	script_tag( name: "insight", value: "R?mi Denis-Courmont discovered that dbus, a message bus application,
is not properly limiting the nesting level when examining messages with
extensive nested variants.  This allows an attacker to crash the dbus system
daemon due to a call stack overflow via crafted messages.


For the stable distribution (lenny), this problem has been fixed in
version 1.2.1-5+lenny2.

For the testing distribution (squeeze), this problem has been fixed in
version 1.2.24-4.

For the unstable distribution (sid), this problem has been fixed in
version 1.2.24-4." );
	script_tag( name: "solution", value: "We recommend that you upgrade your dbus packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to dbus
announced via advisory DSA 2149-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dbus", ver: "1.2.1-5+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-1-doc", ver: "1.2.1-5+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-x11", ver: "1.2.1-5+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdbus-1-3", ver: "1.2.1-5+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdbus-1-dev", ver: "1.2.1-5+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus", ver: "1.2.24-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-1-dbg", ver: "1.2.24-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-1-doc", ver: "1.2.24-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-x11", ver: "1.2.24-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdbus-1-3", ver: "1.2.24-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdbus-1-dev", ver: "1.2.24-4", rls: "DEB6" ) ) != NULL){
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

