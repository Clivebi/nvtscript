if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71460" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-2944" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 02:56:22 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2484-1 (nut)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202484-1" );
	script_tag( name: "insight", value: "Sebastian Pohle discovered that upsd, the server of Network UPS Tools
(NUT) is vulnerable to a remote denial of service attack.

For the stable distribution (squeeze), this problem has been fixed in
version 2.4.3-1.1squeeze2.

For the testing distribution (wheezy) and unstable distribution (sid),
this problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your nut packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to nut
announced via advisory DSA 2484-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libupsclient1", ver: "2.4.3-1.1squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libupsclient1-dev", ver: "2.4.3-1.1squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nut", ver: "2.4.3-1.1squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nut-cgi", ver: "2.4.3-1.1squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nut-hal-drivers", ver: "2.4.3-1.1squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nut-powerman-pdu", ver: "2.4.3-1.1squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nut-snmp", ver: "2.4.3-1.1squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nut-xml", ver: "2.4.3-1.1squeeze2", rls: "DEB6" ) ) != NULL){
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

