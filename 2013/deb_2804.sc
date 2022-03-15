if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702804" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-6387", "CVE-2013-6386", "CVE-2013-6385", "CVE-2013-6389", "CVE-2013-6388" );
	script_name( "Debian Security Advisory DSA 2804-1 (drupal7 - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-11-26 00:00:00 +0100 (Tue, 26 Nov 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2804.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "drupal7 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 7.14-2+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 7.24-1.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in Drupal, a fully-featured
content management framework: Cross-site request forgery, insecure
pseudo random number generation, code execution, incorrect security token
validation and cross-site scripting.

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
if(( res = isdpkgvuln( pkg: "drupal7", ver: "7.14-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

