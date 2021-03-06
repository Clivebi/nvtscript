if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69332" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0520" );
	script_name( "Debian Security Advisory DSA 2196-1 (maradns)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202196-1" );
	script_tag( name: "insight", value: "Witold Baryluk discovered that MaraDNS, a simple security-focused
Domain Name Service server, may overflow an internal buffer when
handling requests with a large number of labels, causing a server
crash and the consequent denial of service.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.3.07.09-2.1.

For the stable distribution (squeeze) and greater this problem had
already been fixed in version 1.4.03-1.1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your maradns packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to maradns
announced via advisory DSA 2196-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "maradns", ver: "1.3.07.09-2.1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "maradns", ver: "1.4.03-1.1", rls: "DEB6" ) ) != NULL){
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

