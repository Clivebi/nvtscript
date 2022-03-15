if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69336" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Debian Security Advisory DSA 2200-1 (iceweasel)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202200-1" );
	script_tag( name: "insight", value: "This update for Iceweasel, a web browser based on Firefox, updates the
certificate blacklist for several fraudulent HTTPS certificates.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.9.0.19-9 of the xulrunner source package.

For the stable distribution (squeeze), this problem has been fixed in
version 3.5.16-6.

For the unstable distribution (sid), this problem has been fixed in
version 3.5.18-1.

For the experimental distribution, this problem has been fixed in
version 4.0~rc2-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your iceweasel packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to iceweasel
announced via advisory DSA 2200-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "iceweasel", ver: "3.5.16-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-dbg", ver: "3.5.16-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs-dev", ver: "1.9.1.16-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs2d", ver: "1.9.1.16-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs2d-dbg", ver: "1.9.1.16-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spidermonkey-bin", ver: "1.9.1.16-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-1.9.1", ver: "1.9.1.16-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-1.9.1-dbg", ver: "1.9.1.16-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-dev", ver: "1.9.1.16-8", rls: "DEB6" ) ) != NULL){
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

