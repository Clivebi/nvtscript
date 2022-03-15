if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72563" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-4731" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-16 03:09:39 -0500 (Fri, 16 Nov 2012)" );
	script_name( "Debian Security Advisory DSA 2568-1 (rtfm)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202568-1" );
	script_tag( name: "insight", value: "IT was discovered that RTFM, the FAQ manager for Request Tracker,
allows authenticated users to create articles in any class.

For the stable distribution (squeeze), this problem has been fixed in
version 2.4.2-4+squeeze2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your rtfm packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to rtfm
announced via advisory DSA 2568-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "rt3.8-rtfm", ver: "2.4.2-4+squeeze2", rls: "DEB6" ) ) != NULL){
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

