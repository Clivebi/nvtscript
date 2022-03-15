if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702999" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-5265", "CVE-2014-5266", "CVE-2014-5267" );
	script_name( "Debian Security Advisory DSA 2999-1 (drupal7 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-08-09 00:00:00 +0200 (Sat, 09 Aug 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2999.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "drupal7 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 7.14-2+deb7u6.

For the testing distribution (jessie), this problem has been fixed in
version 7.31-1.

For the unstable distribution (sid), this problem has been fixed in
version 7.31-1.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "summary", value: "A denial of service vulnerability was discovered in Drupal, a
fully-featured content management framework. A remote attacker could
exploit this flaw to cause CPU and memory exhaustion and the site's
database to reach the maximum number of open connections, leading to the
site becoming unavailable or unresponsive." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "drupal7", ver: "7.14-2+deb7u6", rls: "DEB7" ) ) != NULL){
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

