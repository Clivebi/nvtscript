if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70703" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-1644", "CVE-2010-1645", "CVE-2010-2543", "CVE-2010-2545", "CVE-2011-4824" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:26:57 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2384-1 (cacti)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202384-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in cacti, a graphing tool
for monitoring data. Multiple cross site scripting issues allow remote
attackers to inject arbitrary web script or HTML. An SQL injection
vulnerability allows remote attackers to execute arbitrary SQL commands.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.8.7b-2.1+lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 0.8.7g-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.7i-2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your cacti packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to cacti
announced via advisory DSA 2384-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cacti", ver: "0.8.7b-2.1+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cacti", ver: "0.8.7g-1+squeeze1", rls: "DEB6" ) ) != NULL){
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

