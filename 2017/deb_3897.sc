if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703897" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_cve_id( "CVE-2015-7943", "CVE-2017-6922" );
	script_name( "Debian Security Advisory DSA 3897-1 (drupal7 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-24 00:00:00 +0200 (Sat, 24 Jun 2017)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-08 15:49:00 +0000 (Wed, 08 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3897.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "drupal7 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 7.32-1+deb8u9.

For the stable distribution (stretch), these problems have been fixed in
version 7.52-2+deb9u1. For the stable distribution (stretch),
CVE-2015-7943
was already fixed before the initial release.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "summary", value: "Two vulnerabilities were discovered in Drupal, a fully-featured content
management framework. The Common Vulnerabilities and Exposures project
identifies the following issues:

CVE-2015-7943
Samuel Mortenson and Pere Orga discovered that the overlay module
does not sufficiently validate URLs prior to displaying their
contents, leading to an open redirect vulnerability.

CVE-2017-6922
Greg Knaddison, Mori Sugimoto and iancawthorne discovered that files
uploaded by anonymous users into a private file system can be
accessed by other anonymous users leading to an access bypass
vulnerability." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "drupal7", ver: "7.32-1+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "drupal7", ver: "7.52-2+deb9u1", rls: "DEB9" ) ) != NULL){
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

