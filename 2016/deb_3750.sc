if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703750" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_cve_id( "CVE-2016-10033", "CVE-2016-10045" );
	script_name( "Debian Security Advisory DSA 3750-1 (libphp-phpmailer - security update)" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2017-01-05 13:19:04 +0530 (Thu, 05 Jan 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3750.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libphp-phpmailer on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 5.2.9+dfsg-2+deb8u2.

For the unstable distribution (sid), this problem has been fixed in
version 5.2.14+dfsg-2.1.

We recommend that you upgrade your libphp-phpmailer packages." );
	script_tag( name: "summary", value: "Dawid Golunski discovered that PHPMailer,
a popular library to send email from PHP applications, allowed a remote attacker to
execute code if they were able to provide a crafted Sender address.

Note that for this issue also CVE-2016-10045 was assigned, which is a regression in
the original patch proposed for CVE-2016-10033. Because the original patch was not
applied in Debian, Debian was not vulnerable to CVE-2016-10045." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libphp-phpmailer", ver: "5.2.9+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
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

