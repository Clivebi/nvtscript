if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702642" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1775", "CVE-2013-2777", "CVE-2013-2776", "CVE-2013-1776" );
	script_name( "Debian Security Advisory DSA 2642-1 (sudo - several issues)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-03-09 00:00:00 +0100 (Sat, 09 Mar 2013)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2642.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "sudo on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), these problems have been fixed in
version 1.7.4p4-2.squeeze.4.

For the testing (wheezy) and unstable (sid) distributions, these problems
have been fixed in version 1.8.5p2-1+nmu1.

We recommend that you upgrade your sudo packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in sudo, a program designed
to allow a sysadmin to give limited root privileges to users. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-1775
Marco Schoepl discovered an authentication bypass when the clock is
set to the UNIX epoch [00:00:00 UTC on 1 January 1970].

CVE-2013-1776
Ryan Castellucci and James Ogden discovered aspects of an issue that
would allow session id hijacking from another authorized tty." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "sudo", ver: "1.7.4p4-2.squeeze.4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sudo-ldap", ver: "1.7.4p4-2.squeeze.4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sudo", ver: "1.8.5p2-1+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sudo-ldap", ver: "1.8.5p2-1+nmu1", rls: "DEB7" ) ) != NULL){
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

