if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891604" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2018-19787" );
	script_name( "Debian LTS: Security Advisory for lxml (DLA-1604-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-12-11 00:00:00 +0100 (Tue, 11 Dec 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-26 21:15:00 +0000 (Thu, 26 Nov 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/12/msg00001.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "lxml on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in lxml version
3.4.0-1+deb8u1.

We recommend that you upgrade your lxml packages." );
	script_tag( name: "summary", value: "It was discovered that there was an XSS injection vulnerability in
the LXML HTML/XSS manipulation library for Python.

LXML did not remove 'javascript:' URLs that used escaping such as
'j a v a s c r i p t'. This is a similar issue to CVE-2014-3146." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-lxml", ver: "3.4.0-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-lxml-dbg", ver: "3.4.0-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-lxml-doc", ver: "3.4.0-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-lxml", ver: "3.4.0-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-lxml-dbg", ver: "3.4.0-1+deb8u1", rls: "DEB8" ) )){
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

