if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69729" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_cve_id( "CVE-2011-1518" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Debian Security Advisory DSA 2231-1 (otrs2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202231-1" );
	script_tag( name: "insight", value: "Multiple cross-site scripting vulnerabilities were discovered in Open
Ticket Request System (OTRS), a trouble-ticket system. (CVE-2011-1518)

In addition, this security update a failure when upgrading the package
from lenny to squeeze.

The oldstable distribution (lenny) is not affected by this problem.

For the stable distribution (squeeze), this problem has been fixed in
version 2.4.9+dfsg1-3+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 2.4.10+dfsg1-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your otrs2 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to otrs2
announced via advisory DSA 2231-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "otrs2", ver: "2.4.9+dfsg1-3+squeeze1", rls: "DEB6" ) ) != NULL){
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
