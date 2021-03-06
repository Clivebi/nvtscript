if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69108" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-1002" );
	script_name( "Debian Security Advisory DSA 2174-1 (avahi)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_tag( name: "insight", value: "It was discovered that avahi, an implementation of the zeroconf protocol,
can be crashed remotely by a single UDP packet, which may result in a
denial of service." );
	script_tag( name: "summary", value: "The remote host is missing an update to avahi
announced via advisory DSA 2174-1." );
	script_tag( name: "solution", value: "For the oldstable distribution (lenny), this problem has been fixed in
version 0.6.23-3lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 0.6.27-2+squeeze1.

For the testing (wheezy) and unstable distribution (sid), this problem
has been fixed in version 0.6.28-4.

We recommend that you upgrade your avahi packages." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202174-1" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "avahi-autoipd", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-daemon", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-dbg", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-discover", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-dnsconfd", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-ui-utils", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-utils", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-client-dev", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-client3", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-common-data", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-common-dev", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-common3", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-compat-howl-dev", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-compat-howl0", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-compat-libdnssd-dev", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-compat-libdnssd1", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-core-dev", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-core5", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-glib-dev", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-glib1", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-gobject-dev", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-gobject0", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-qt3-1", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-qt3-dev", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-qt4-1", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-qt4-dev", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-ui-dev", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-ui0", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-avahi", ver: "0.6.23-3lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-autoipd", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-daemon", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-dbg", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-discover", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-dnsconfd", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-ui-utils", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "avahi-utils", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-client-dev", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-client3", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-common-data", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-common-dev", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-common3", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-compat-libdnssd-dev", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-compat-libdnssd1", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-core-dev", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-core7", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-glib-dev", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-glib1", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-gobject-dev", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-gobject0", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-qt3-1", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-qt3-dev", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-qt4-1", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-qt4-dev", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-ui-dev", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavahi-ui0", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-avahi", ver: "0.6.27-2+squeeze1", rls: "DEB6" ) ) != NULL){
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

