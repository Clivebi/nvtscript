if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70700" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-4096" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:26:32 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2381-1 (squid3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202381-1" );
	script_tag( name: "insight", value: "It was discovered that the IPv6 support code in Squid does not
properly handle certain DNS responses, resulting in deallocation of an
invalid pointer and a daemon crash.

The squid package and the version of squid3 shipped in lenny lack IPv6
support and are not affected by this issue.

For the stable distribution (squeeze), this problem has been fixed in
version 3.1.6-1.2+squeeze2.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 3.1.18-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your squid3 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to squid3
announced via advisory DSA 2381-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.1.6-1.2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3", ver: "3.1.6-1.2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3-common", ver: "3.1.6-1.2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3-dbg", ver: "3.1.6-1.2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squidclient", ver: "3.1.6-1.2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.1.18-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3", ver: "3.1.18-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3-common", ver: "3.1.18-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3-dbg", ver: "3.1.18-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squidclient", ver: "3.1.18-1", rls: "DEB7" ) ) != NULL){
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

