if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703343" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-7809" );
	script_name( "Debian Security Advisory DSA 3343-1 (twig - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-26 00:00:00 +0200 (Wed, 26 Aug 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3343.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "twig on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 1.16.2-1+deb8u1.

For the testing (stretch) and unstable (sid) distributions, this
problem has been fixed in version 1.20.0-1.

We recommend that you upgrade your twig packages." );
	script_tag( name: "summary", value: "James Kettle, Alain Tiemblo, Christophe Coevoet and Fabien Potencier
discovered that twig, a templating engine for PHP, did not correctly
process its input. End users allowed to submit twig templates could
use specially crafted code to trigger remote code execution, even in
sandboxed templates." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "php-twig", ver: "1.16.2-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php-twig-doc", ver: "1.16.2-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-twig", ver: "1.16.2-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

