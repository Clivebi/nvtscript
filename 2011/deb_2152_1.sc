if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68990" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-4267" );
	script_name( "Debian Security Advisory DSA 2152-1 (hplip)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202152-1" );
	script_tag( name: "insight", value: "Sebastian Krahmer discovered a buffer overflow in the SNMP discovery code
of the HP Linux Printing and Imaging System, which could result in the
execution of arbitrary code.

For the stable distribution (lenny), this problem has been fixed in
version 2.8.6.b-4+lenny1.

For the testing distribution (squeeze), this problem has been fixed in
version 3.10.6-2.

For the unstable distribution (sid), this problem has been fixed in
version 3.10.6-2.

For the experimental distribution, this problem has been fixed in
version 3.11.1-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your hplip packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to hplip
announced via advisory DSA 2152-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "hpijs", ver: "2.8.6.b-4+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hpijs-ppds", ver: "2.8.6.b-4+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip", ver: "2.8.6.b-4+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-data", ver: "2.8.6.b-4+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-dbg", ver: "2.8.6.b-4+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-doc", ver: "2.8.6.b-4+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-gui", ver: "2.8.6.b-4+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hpijs", ver: "3.10.6-2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hpijs-ppds", ver: "3.10.6-2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip", ver: "3.10.6-2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-cups", ver: "3.10.6-2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-data", ver: "3.10.6-2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-dbg", ver: "3.10.6-2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-doc", ver: "3.10.6-2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-gui", ver: "3.10.6-2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libhpmud-dev", ver: "3.10.6-2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libhpmud0", ver: "3.10.6-2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsane-hpaio", ver: "3.10.6-2", rls: "DEB6" ) ) != NULL){
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

