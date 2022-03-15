if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70410" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2011-1058" );
	script_name( "Debian Security Advisory DSA 2321-1 (moin)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202321-1" );
	script_tag( name: "insight", value: "A cross-site scripting vulnerability was discovered in the rst parser of
Moin, a Python clone of WikiWiki.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.7.1-3+lenny6.

For the stable distribution (squeeze), this problem has been fixed in
version 1.9.3-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 1.9.3-3." );
	script_tag( name: "solution", value: "We recommend that you upgrade your moin packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to moin
announced via advisory DSA 2321-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-moinmoin", ver: "1.7.1-3+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-moinmoin", ver: "1.9.3-1+squeeze1", rls: "DEB6" ) ) != NULL){
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

