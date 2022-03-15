if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703391" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-7984" );
	script_name( "Debian Security Advisory DSA 3391-1 (php-horde - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-03 00:00:00 +0100 (Tue, 03 Nov 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3391.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "php-horde on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 5.2.1+debian0-2+deb8u2.

For the testing distribution (stretch) and the unstable distribution
(sid), this problem has been fixed in version 5.2.8+debian0-1.

We recommend that you upgrade your php-horde packages." );
	script_tag( name: "summary", value: "It was discovered that the web-based
administration interface in the Horde Application Framework did not guard against
Cross-Site Request Forgery (CSRF) attacks. As a result, other, malicious web pages
could cause Horde applications to perform actions as the Horde user.

The oldstable distribution (wheezy) did not contain php-horde
packages." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "php-horde", ver: "5.2.8+debian0-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php-horde", ver: "5.2.1+debian0-2+deb8u2", rls: "DEB8" ) ) != NULL){
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

