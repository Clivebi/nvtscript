if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72169" );
	script_cve_id( "CVE-2012-2237" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-08-27T12:57:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:57:20 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-21 14:02:00 +0000 (Sat, 21 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-09-15 04:23:49 -0400 (Sat, 15 Sep 2012)" );
	script_name( "Debian Security Advisory DSA 2540-1 (mahara)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc." );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202540-1" );
	script_tag( name: "insight", value: "Emanuel Bronshtein discovered that Mahara, an electronic portfolio,
weblog, and resume builder, contains multiple cross-site scripting
vulnerabilities due to missing sanitization and insufficient encoding
of user-supplied data.

For the stable distribution (squeeze), these problems have been fixed in
version 1.2.6-2+squeeze5.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.5.1-2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your mahara packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to mahara
announced via advisory DSA 2540-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mahara", ver: "1.2.6-2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mahara-apache2", ver: "1.2.6-2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mahara-mediaplayer", ver: "1.2.6-2+squeeze5", rls: "DEB6" ) ) != NULL){
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

