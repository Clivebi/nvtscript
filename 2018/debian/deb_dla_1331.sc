if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891331" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2018-1000132" );
	script_name( "Debian LTS: Security Advisory for mercurial (DLA-1331-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-02 00:00:00 +0200 (Mon, 02 Apr 2018)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 13:15:00 +0000 (Fri, 31 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00034.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "mercurial on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2.2.2-4+deb7u7.

We recommend that you upgrade your mercurial packages." );
	script_tag( name: "summary", value: "Mercurial version 4.5 and earlier contains a Incorrect Access Control
(CWE-285) vulnerability in Protocol server that can result in
Unauthorized data access. This attack appear to be exploitable via
network connectivity. This vulnerability appears to have been fixed in
4.5.1.

This update also fixes a regression inroduced in 2.2.2-4+deb7u5 which
makes the testsuite fail non-deterministically." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mercurial", ver: "2.2.2-4+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mercurial-common", ver: "2.2.2-4+deb7u7", rls: "DEB7" ) )){
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

