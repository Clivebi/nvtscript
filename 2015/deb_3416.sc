if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703416" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-8476" );
	script_name( "Debian Security Advisory DSA 3416-1 (libphp-phpmailer - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-13 00:00:00 +0100 (Sun, 13 Dec 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3416.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "libphp-phpmailer on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution
(wheezy), this problem has been fixed in version 5.1-1.1.

For the stable distribution (jessie), this problem has been fixed in
version 5.2.9+dfsg-2+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 5.2.14+dfsg-1.

We recommend that you upgrade your libphp-phpmailer packages." );
	script_tag( name: "summary", value: "Takeshi Terada discovered a vulnerability
in PHPMailer, a PHP library for email transfer, used by many CMSs. The library
accepted email addresses and SMTP commands containing line breaks, which can be
abused by an attacker to inject messages." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libphp-phpmailer", ver: "5.1-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libphp-phpmailer", ver: "5.2.9+dfsg-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

