if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69415" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-0727" );
	script_name( "Debian Security Advisory DSA 2205-1 (gdm3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202205-1" );
	script_tag( name: "insight", value: "Sebastian Krahmer discovered that the gdm3, the GNOME Desktop Manager,
does not properly drop privileges when manipulating files related to
the logged-in user.  As a result, local users can gain root
privileges.

The oldstable distribution (lenny) does not contain a gdm3 package.
The gdm package is not affected by this issue.

For the stable distribution (squeeze), this problem has been fixed in
version 2.30.5-6squeeze2.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your gdm3 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to gdm3
announced via advisory DSA 2205-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gdm3", ver: "2.30.5-6squeeze2", rls: "DEB6" ) ) != NULL){
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

