if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703940" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2017-12836" );
	script_name( "Debian Security Advisory DSA 3940-1 (cvs - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-13 00:00:00 +0200 (Sun, 13 Aug 2017)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3940.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "cvs on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 2:1.12.13+real-15+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 2:1.12.13+real-22+deb9u1.

We recommend that you upgrade your cvs packages." );
	script_tag( name: "summary", value: "It was discovered that CVS, a centralised version control system, did
not correctly handle maliciously constructed repository URLs, which
allowed an attacker to run an arbitrary shell command." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cvs", ver: "2:1.12.13+real-22+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cvs", ver: "2:1.12.13+real-15+deb8u1", rls: "DEB8" ) ) != NULL){
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

