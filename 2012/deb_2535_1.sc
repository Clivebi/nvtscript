if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71826" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-2768" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:33:27 -0400 (Thu, 30 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2535-1 (rtfm)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202535-1" );
	script_tag( name: "insight", value: "It was discovered that rtfm, the Request Tracker FAQ Manager, contains
multiple cross-site scripting vulnerabilities in the topic
administration page.

For the stable distribution (squeeze), this problem has been fixed in
version 2.4.2-4+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 4.0.6-4 of the
request-tracker4 package." );
	script_tag( name: "solution", value: "We recommend that you upgrade your rtfm packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to rtfm
announced via advisory DSA 2535-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "rt3.8-rtfm", ver: "2.4.2-4+squeeze1", rls: "DEB6" ) ) != NULL){
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

