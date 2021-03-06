if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69110" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0696", "CVE-2011-0697" );
	script_name( "Debian Security Advisory DSA 2163-2 (dajaxice)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "insight", value: "The changes in python-django DSA-2163 necessary to fix the issues
CVE-2011-0696 and CVE-2011-0697 introduced an unavoidable backward
incompatibility, which caused a regression in dajaxice, which
depends on python-django. This update supplies fixed packages for
dajaxice." );
	script_tag( name: "summary", value: "The remote host is missing an update to dajaxice
announced via advisory DSA 2163-2." );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 0.1.5-1squeeze1.

For the testing (wheezy) and unstable distribution (sid), this problem
has been fixed in version 0.1.8.1-1.

We recommend that you upgrade your dajaxice packages." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202163-2" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-django-dajaxice", ver: "0.1.5-1squeeze1", rls: "DEB6" ) ) != NULL){
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

