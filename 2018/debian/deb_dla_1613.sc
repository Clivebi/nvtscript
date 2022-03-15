if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891613" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2018-20346" );
	script_name( "Debian LTS: Security Advisory for sqlite3 (DLA-1613-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-12-28 00:00:00 +0100 (Fri, 28 Dec 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-23 01:15:00 +0000 (Sun, 23 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/12/msg00012.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "sqlite3 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.8.7.1-1+deb8u3.

We recommend that you upgrade your sqlite3 packages." );
	script_tag( name: "summary", value: "Security experts at Tencent's Blade security team have discovered a
critical vulnerability in SQLite database software (nicknamed 'Magellan').

The 'Magellan' remote code execution vulnerability has now been fixed by
adding extra defenses against strategically corrupt databases to fts3/4." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "lemon", ver: "3.8.7.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsqlite3-0", ver: "3.8.7.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsqlite3-0-dbg", ver: "3.8.7.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsqlite3-dev", ver: "3.8.7.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsqlite3-tcl", ver: "3.8.7.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sqlite3", ver: "3.8.7.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sqlite3-doc", ver: "3.8.7.1-1+deb8u3", rls: "DEB8" ) )){
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

