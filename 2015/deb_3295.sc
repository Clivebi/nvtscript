if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703295" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-2665", "CVE-2015-4342", "CVE-2015-4454" );
	script_name( "Debian Security Advisory DSA 3295-1 (cacti - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-24 00:00:00 +0200 (Wed, 24 Jun 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3295.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "cacti on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 0.8.8a+dfsg-5+deb7u5.

For the stable distribution (jessie), these problems have been fixed in
version 0.8.8b+dfsg-8+deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 0.8.8d+ds1-1.

We recommend that you upgrade your cacti packages." );
	script_tag( name: "summary", value: "Several vulnerabilities (cross-site
scripting and SQL injection) have been discovered in Cacti, a web interface for
graphing of monitoring systems." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cacti", ver: "0.8.8a+dfsg-5+deb7u5", rls: "DEB7" ) ) != NULL){
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

