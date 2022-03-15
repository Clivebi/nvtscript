if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704351" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-19296" );
	script_name( "Debian Security Advisory DSA 4351-1 (libphp-phpmailer - security update)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-12-07 00:00:00 +0100 (Fri, 07 Dec 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-21 18:34:00 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4351.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "libphp-phpmailer on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 5.2.14+dfsg-2.3+deb9u1.

We recommend that you upgrade your libphp-phpmailer packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/libphp-phpmailer" );
	script_tag( name: "summary", value: "It was discovered that PHPMailer, a library to send email from PHP
applications, is prone to a PHP object injection vulnerability,
potentially allowing a remote attacker to execute arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libphp-phpmailer", ver: "5.2.14+dfsg-2.3+deb9u1", rls: "DEB9" ) )){
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

