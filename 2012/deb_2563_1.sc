if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72534" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-5024", "CVE-2012-3356", "CVE-2012-3357", "CVE-2012-4533" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-29 10:19:52 -0400 (Mon, 29 Oct 2012)" );
	script_name( "Debian Security Advisory DSA 2563-1 (viewvc)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202563-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were found in ViewVC, a web interface for CVS
and Subversion repositories.

CVE-2009-5024: remote attackers can bypass the cvsdb row_limit
configuration setting, and consequently conduct resource-consumption
attacks via the limit parameter.

CVE-2012-3356: the remote SVN views functionality does not properly
perform authorization, which allows remote attackers to bypass intended
access restrictions.

CVE-2012-3357: the SVN revision view does not properly handle log
messages when a readable path is copied from an unreadable path, which
allows remote attackers to obtain sensitive information.

CVE-2012-4533: function name lines returned by diff are not properly
escaped, allowing attackers with commit access to perform cross site
scripting.

For the stable distribution (squeeze), these problems have been fixed in
version 1.1.5-1.1+squeeze2.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.1.5-1.4." );
	script_tag( name: "solution", value: "We recommend that you upgrade your viewvc packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to viewvc
announced via advisory DSA 2563-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "viewvc", ver: "1.1.5-1.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "viewvc-query", ver: "1.1.5-1.1+squeeze2", rls: "DEB6" ) ) != NULL){
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

