if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68983" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2011-0007" );
	script_name( "Debian Security Advisory DSA 2147-1 (pimd)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202147-1" );
	script_tag( name: "insight", value: "Vincent Bernat discovered that pimd, a multicast routing daemon, creates
files with predictable names upon the receipt of particular signals.

For the stable distribution (lenny), this problem has been fixed in
version 2.1.0-alpha29.17-8.1lenny1.

The testing distribution (squeeze) and the unstable distribution (sid)
will receive updates shortly." );
	script_tag( name: "solution", value: "We recommend that you upgrade your pimd packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to pimd
announced via advisory DSA 2147-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "pimd", ver: "2.1.0-alpha29.17-8.1lenny1", rls: "DEB5" ) ) != NULL){
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

