if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71254" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-1182" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:56:34 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Debian Security Advisory DSA 2450-1 (samba)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202450-1" );
	script_tag( name: "insight", value: "It was discovered that Samba, the SMB/CIFS file, print, and login server,
contained a flaw in the remote procedure call (RPC) code which allowed
remote code execution as the super user from an unauthenticated
connection.

For the stable distribution (squeeze), this problem has been fixed in
version 2:3.5.6~dfsg-3squeeze7.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 2:3.6.4-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your samba packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to samba
announced via advisory DSA 2450-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpam-smbpass", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient-dev", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwbclient0", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-common", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-common-bin", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-dbg", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-doc", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-doc-pdf", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-tools", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "smbclient", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "swat", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "winbind", ver: "2:3.5.6~dfsg-3squeeze7", rls: "DEB6" ) ) != NULL){
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

