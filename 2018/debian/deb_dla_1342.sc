if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891342" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-8763" );
	script_name( "Debian LTS: Security Advisory for ldap-account-manager (DLA-1342-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-09 00:00:00 +0200 (Mon, 09 Apr 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-19 19:19:00 +0000 (Thu, 19 Apr 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/04/msg00007.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ldap-account-manager on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.7-2+deb7u1.

We recommend that you upgrade your ldap-account-manager packages." );
	script_tag( name: "summary", value: "Michal Kedzior found two vulnerabilities in LDAP Account Manager, a web
front-end for LDAP directories.

CVE-2018-8763

The found Reflected Cross Site Scripting (XSS) vulnerability might
allow an attacker to execute JavaScript code in the browser of the
victim or to redirect her to a malicious website if the victim clicks
on a specially crafted link." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ldap-account-manager", ver: "3.7-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ldap-account-manager-lamdaemon", ver: "3.7-2+deb7u1", rls: "DEB7" ) )){
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

