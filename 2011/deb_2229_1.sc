if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69571" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Debian Security Advisory DSA 2229-1 (spip)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202229-1" );
	script_tag( name: "insight", value: "A vulnerability has been found in SPIP, a website engine for publishing,
which allows a malicious registered author to disconnect the website
from its database, resulting in denial of service.

The oldstable distribution (lenny) doesn't include spip.

For the stable distribution (squeeze), this problem has been fixed in
version 2.1.1-3squeeze1.

The unstable distribution (sid) will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your spip packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to spip
announced via advisory DSA 2229-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "spip", ver: "2.1.1-3squeeze1", rls: "DEB6" ) ) != NULL){
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

