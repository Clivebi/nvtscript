if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71463" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-0791" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 02:56:45 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2485-1 (imp4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202485-1" );
	script_tag( name: "insight", value: "Multiple cross-site scripting (XSS) vulnerabilities were discovered in
IMP, the webmail component in the Horde framework. The vulnerabilities
allow remote attackers to inject arbitrary web script or HTML via various
crafted parameters.

For the stable distribution (squeeze), this problem has been fixed in
version 4.3.7+debian0-2.2.

For the testing distribution (wheezy) and unstable distribution (sid),
this problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your imp4 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to imp4
announced via advisory DSA 2485-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "imp4", ver: "4.3.7+debian0-2.2", rls: "DEB6" ) ) != NULL){
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

