if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703291" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-3231", "CVE-2015-3232", "CVE-2015-3233", "CVE-2015-3234" );
	script_name( "Debian Security Advisory DSA 3291-1 (drupal7 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-18 00:00:00 +0200 (Thu, 18 Jun 2015)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3291.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "drupal7 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), these problems have been fixed
in version 7.14-2+deb7u10.

For the stable distribution (jessie), these problems have been fixed in
version 7.32-1+deb8u4.

For the unstable distribution (sid), these problems have been fixed in
version 7.38.1.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were found in drupal7, a content management
platform used to power websites.

CVE-2015-3231Incorrect cache handling made private content viewed by user 1

exposed to other, non-privileged users.

CVE-2015-3232
A flaw in the Field UI module made it possible for attackers to
redirect users to malicious sites.

CVE-2015-3233
Due to insufficient URL validation, the Overlay module could be
used to redirect users to malicious sites.

CVE-2015-3234
The OpenID module allowed an attacker to log in as other users,
including administrators." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "drupal7", ver: "7.14-2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "drupal7", ver: "7.32-1+deb8u4", rls: "DEB8" ) ) != NULL){
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

