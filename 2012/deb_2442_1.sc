if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71245" );
	script_cve_id( "CVE-2010-5077" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:55:18 -0400 (Mon, 30 Apr 2012)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Debian Security Advisory DSA 2442-1 (openarena)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202442-1" );
	script_tag( name: "insight", value: "It has been discovered that spoofed getstatus UDP requests are being
sent by attackers to servers for use with games derived from the
Quake 3 engine (such as openarena).  These servers respond with a
packet flood to the victim whose IP address was impersonated by the
attackers, causing a denial of service.

For the stable distribution (squeeze), this problem has been fixed in
version 0.8.5-5+squeeze2.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 0.8.5-6." );
	script_tag( name: "solution", value: "We recommend that you upgrade your openarena packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to openarena
announced via advisory DSA 2442-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "openarena", ver: "0.8.5-5+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openarena-server", ver: "0.8.5-5+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openarena", ver: "0.8.8-3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openarena-dbg", ver: "0.8.8-3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openarena-server", ver: "0.8.8-3", rls: "DEB7" ) ) != NULL){
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

