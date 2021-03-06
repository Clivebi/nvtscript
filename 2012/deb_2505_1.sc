if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71484" );
	script_cve_id( "CVE-2012-3363" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:07:40 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2505-1 (zendframework)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202505-1" );
	script_tag( name: "insight", value: "An XML External Entities inclusion vulnerability was discovered in
Zend Framework, a PHP library.  This vulnerability may allow attackers
to access to local files, depending on how the framework is used.

For the stable distribution (squeeze), this problem has been fixed in
version 1.10.6-1squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 1.11.12-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your zendframework packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to zendframework
announced via advisory DSA 2505-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "zendframework", ver: "1.10.6-1squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zendframework-bin", ver: "1.10.6-1squeeze1", rls: "DEB6" ) ) != NULL){
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

