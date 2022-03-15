if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71136" );
	script_cve_id( "CVE-2012-0210", "CVE-2012-0211", "CVE-2012-0212" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:30:53 -0400 (Mon, 12 Mar 2012)" );
	script_name( "Debian Security Advisory DSA 2409-1 (devscripts)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202409-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in debdiff, a script used
to compare two Debian packages, which is part of the devscripts package.
The following Common Vulnerabilities and Exposures project ids have been
assigned to identify them:

CVE-2012-0210:

Paul Wise discovered that due to insufficient input sanitising when
processing .dsc and .changes files, it is possible to execute
arbitrary code and disclose system information.

CVE-2012-0211:

Raphael Geissert discovered that it is possible to inject or modify
arguments of external commands when processing source packages with
specially-named tarballs in the top-level directory of the .orig
tarball, allowing arbitrary code execution.

CVE-2012-0212:

Raphael Geissert discovered that it is possible to inject or modify
arguments of external commands when passing as argument to debdiff
a specially-named file, allowing arbitrary code execution.


For the stable distribution (squeeze), these problems have been fixed in
version 2.10.69+squeeze2.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems will be fixed in
version 2.11.4." );
	script_tag( name: "solution", value: "We recommend that you upgrade your devscripts packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to devscripts
announced via advisory DSA 2409-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "devscripts", ver: "2.10.69+squeeze2", rls: "DEB6" ) ) != NULL){
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

