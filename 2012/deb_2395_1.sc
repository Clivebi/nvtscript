if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70713" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-3483", "CVE-2012-0041", "CVE-2012-0042", "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-0068" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:29:37 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2395-1 (wireshark)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202395-1" );
	script_tag( name: "insight", value: "Laurent Butti discovered a buffer underflow in the LANalyzer dissector
of the Wireshark network traffic analyzer, which could lead to the
execution of arbitrary code (CVE-2012-0068)

This update also addresses several bugs, which can lead to crashes of
Wireshark. These are not treated as security issues, but are fixed
nonetheless if security updates are scheduled: CVE-2011-3483,
CVE-2012-0041, CVE-2012-0042, CVE-2012-0066 and CVE-2012-0067.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.11-6+squeeze6.

For the unstable distribution (sid), this problem has been fixed in
version 1.6.5-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your wireshark packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to wireshark
announced via advisory DSA 2395-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "tshark", ver: "1.2.11-6+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark", ver: "1.2.11-6+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-common", ver: "1.2.11-6+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dbg", ver: "1.2.11-6+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dev", ver: "1.2.11-6+squeeze6", rls: "DEB6" ) ) != NULL){
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

