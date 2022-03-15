if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70699" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-2697", "CVE-2011-2964" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:26:17 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2380-1 (foomatic-filters)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202380-1" );
	script_tag( name: "insight", value: "It was discovered that the foomatic-filters, a support package for
setting up printers, allowed authenticated users to submit crafted
print jobs which would execute shell commands on the print servers.

CVE-2011-2697 was assigned to the vulnerability in the Perl
implementation included in lenny, and CVE-2011-2964 to the
vulnerability affecting the C reimplementation part of squeeze.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.0.2-20080211-3.2+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 4.0.5-6+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 4.0.9-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your foomatic-filters packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to foomatic-filters
announced via advisory DSA 2380-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "foomatic-filters", ver: "3.0.2-20080211-3.2+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "foomatic-filters", ver: "4.0.5-6+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "foomatic-filters", ver: "4.0.9-1", rls: "DEB7" ) ) != NULL){
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

