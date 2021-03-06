if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702901" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-0165", "CVE-2014-0166" );
	script_name( "Debian Security Advisory DSA 2901-1 (wordpress - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-12 00:00:00 +0200 (Sat, 12 Apr 2014)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2901.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze),
these problems have been fixed in version 3.6.1+dfsg-1~deb6u2.

For the stable distribution (wheezy), these problems have been fixed in
version 3.6.1+dfsg-1~deb7u2.

For the testing distribution (jessie), these problems have been fixed in
version 3.8.2+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in
version 3.8.2+dfsg-1.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in Wordpress, a web blogging tool. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2014-0165
A user with a contributor role, using a specially crafted
request, can publish posts, which is reserved for users of the
next-higher role.

CVE-2014-0166
Jon Cave of the WordPress security team discovered that the
wp_validate_auth_cookie function in wp-includes/pluggable.php does
not properly determine the validity of authentication cookies,
allowing a remote attacker to obtain access via a forged cookie." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "wordpress", ver: "3.6.1+dfsg-1~deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "3.6.1+dfsg-1~deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress", ver: "3.6.1+dfsg-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "3.6.1+dfsg-1~deb7u2", rls: "DEB7" ) ) != NULL){
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

