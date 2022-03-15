if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704094" );
	script_version( "2021-06-16T13:21:12+0000" );
	script_cve_id( "CVE-2017-1000480" );
	script_name( "Debian Security Advisory DSA 4094-1 (smarty3 - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 13:21:12 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-22 00:00:00 +0100 (Mon, 22 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-04 02:29:00 +0000 (Sun, 04 Feb 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4094.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "smarty3 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 3.1.21-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 3.1.31+20161214.1.c7d42e4+selfpack1-2+deb9u1.

We recommend that you upgrade your smarty3 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/smarty3" );
	script_tag( name: "summary", value: "It was discovered that Smarty, a PHP template engine, was vulnerable to
code-injection attacks. An attacker was able to craft a filename in
comments that could lead to arbitrary code execution on the host running
Smarty." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "smarty3", ver: "3.1.31+20161214.1.c7d42e4+selfpack1-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "smarty3", ver: "3.1.21-1+deb8u1", rls: "DEB8" ) )){
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

