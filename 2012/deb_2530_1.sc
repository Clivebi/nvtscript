if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71825" );
	script_cve_id( "CVE-2012-3478" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:33:25 -0400 (Thu, 30 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2530-1 (rssh)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202530-1" );
	script_tag( name: "insight", value: "Henrik Erkkonen discovered that rssh, a restricted shell for SSH, does
not properly restrict shell access.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3.2-13squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 2.3.3-5." );
	script_tag( name: "solution", value: "We recommend that you upgrade your rssh packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to rssh
announced via advisory DSA 2530-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "rssh", ver: "2.3.2-13squeeze1", rls: "DEB6" ) ) != NULL){
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

