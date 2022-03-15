if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70706" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-3341", "CVE-2011-3342", "CVE-2011-3343" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:27:32 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2386-1 (openttd)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202386-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in openttd, a transport
business simulation game. Multiple buffer overflows and off-by-one
errors allow remote attackers to cause denial of service.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.6.2-1+lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 1.0.4-4.

For the unstable distribution (sid), this problem has been fixed in
version 1.1.4-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your openttd packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to openttd
announced via advisory DSA 2386-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "openttd", ver: "0.6.2-1+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openttd", ver: "1.0.4-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openttd-data", ver: "1.0.4-4", rls: "DEB6" ) ) != NULL){
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

