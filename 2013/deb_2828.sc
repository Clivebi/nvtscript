if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702828" );
	script_version( "$Revision: 14276 $" );
	script_cve_id( "CVE-2013-6385", "CVE-2013-6386" );
	script_name( "Debian Security Advisory DSA 2828-1 (drupal6 - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-28 00:00:00 +0100 (Sat, 28 Dec 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2828.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "drupal6 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 6.29-1.

We recommend that you upgrade your drupal6 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in Drupal, a fully-featured
content management framework: vulnerabilities due to optimistic cross-site
request forgery protection, insecure pseudo random number generation, code
execution and incorrect security token validation.

In order to avoid the remote code execution vulnerability, it is
recommended to create a .htaccess file (or an equivalent configuration
directive in case you are not using Apache to serve your Drupal sites)
in each of your sites' files
directories (both public and private, in
case you have both configured).

Please refer to the NEWS file provided with this update and the upstream
advisory at drupal.org/SA-CORE-2013-003
for further information." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "drupal6", ver: "6.29-1", rls: "DEB6" ) ) != NULL){
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

