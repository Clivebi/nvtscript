if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703075" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-9015", "CVE-2014-9016" );
	script_name( "Debian Security Advisory DSA 3075-1 (drupal7 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-11-20 00:00:00 +0100 (Thu, 20 Nov 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3075.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "drupal7 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 7.14-2+deb7u8.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "summary", value: "Two vulnerabilities were discovered in Drupal, a fully-featured content
management framework. The Common Vulnerabilities and Exposures project
identifies the following issues:

CVE-2014-9015
Aaron Averill discovered that a specially crafted request can give a
user access to another user's session, allowing an attacker to
hijack a random session.

CVE-2014-9016
Michael Cullum, Javier Nieto and Andres Rojas Guerrero discovered
that the password hashing API allows an attacker to send
specially crafted requests resulting in CPU and memory
exhaustion. This may lead to the site becoming unavailable or
unresponsive (denial of service).

Custom configured session.inc and password.inc need to be audited as
well to verify if they are prone to these vulnerabilities." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "drupal7", ver: "7.14-2+deb7u8", rls: "DEB7" ) ) != NULL){
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

