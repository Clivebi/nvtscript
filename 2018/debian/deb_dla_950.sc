if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890950" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2017-6891" );
	script_name( "Debian LTS: Security Advisory for libtasn1-3 (DLA-950-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-25 00:00:00 +0100 (Thu, 25 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-05 15:29:00 +0000 (Wed, 05 Jun 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/05/msg00021.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libtasn1-3 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', this problem has been fixed in version
2.13-2+deb7u4.

We recommend that you upgrade your libtasn1-3 packages." );
	script_tag( name: "summary", value: "Secunia Research has discovered multiple vulnerabilities in GnuTLS
libtasn1, which can be exploited by malicious people to compromise
a vulnerable system.

Two errors in the 'asn1_find_node()' function (lib/parser_aux.c)
can be exploited to cause a stacked-based buffer overflow.

Successful exploitation of the vulnerabilities allows execution
of arbitrary code but requires tricking a user into processing
a specially crafted assignments file by e.g. asn1Coding utility." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtasn1-3", ver: "2.13-2+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtasn1-3-bin", ver: "2.13-2+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtasn1-3-dbg", ver: "2.13-2+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtasn1-3-dev", ver: "2.13-2+deb7u4", rls: "DEB7" ) )){
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

