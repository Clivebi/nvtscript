if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69109" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-0719" );
	script_name( "Debian Security Advisory DSA 2175-1 (samba)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_tag( name: "insight", value: "Volker Lendecke discovered that missing range checks in Samba's file
descriptor handling could lead to memory corruption, resulting in denial
of service." );
	script_tag( name: "summary", value: "The remote host is missing an update to samba
announced via advisory DSA 2175-1." );
	script_tag( name: "solution", value: "For the oldstable distribution (lenny), this problem has been fixed in
version 3.2.5-4lenny14.

For the stable distribution (squeeze), this problem has been fixed in
version 3.5.6~dfsg-3squeeze2.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your samba packages." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202175-1" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpam-smbpass", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient-dev", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwbclient0", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-common", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-dbg", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-doc", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-doc-pdf", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-tools", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "smbclient", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "smbfs", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "swat", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "winbind", ver: "3.2.5-4lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-smbpass", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsmbclient-dev", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwbclient0", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-common", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-common-bin", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-dbg", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-doc", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-doc-pdf", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "samba-tools", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "smbclient", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "swat", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "winbind", ver: "3.5.6~dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
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

