if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71141" );
	script_cve_id( "CVE-2012-0869" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:31:28 -0400 (Mon, 12 Mar 2012)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Debian Security Advisory DSA 2414-1 (fex)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202414-1" );
	script_tag( name: "insight", value: "Nicola Fioravanti discovered that F*X, a web service for transferring
very large files, is not properly sanitizing input parameters of the fup
script.  An attacker can use this flaw to conduct reflected cross-site
scripting attacks via various script parameters.

For the stable distribution (squeeze), this problem has been fixed in
version 20100208+debian1-1+squeeze2.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed
in version 20120215-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your fex packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to fex
announced via advisory DSA 2414-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "fex", ver: "20100208+debian1-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "fex-utils", ver: "20100208+debian1-1+squeeze3", rls: "DEB6" ) ) != NULL){
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

