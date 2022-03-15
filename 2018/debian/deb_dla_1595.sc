if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891595" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2018-19490", "CVE-2018-19491", "CVE-2018-19492" );
	script_name( "Debian LTS: Security Advisory for gnuplot5 (DLA-1595-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-26 00:00:00 +0100 (Mon, 26 Nov 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 20:15:00 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/11/msg00031.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "gnuplot5 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
5.0.0~rc+dfsg2-1+deb8u1.

We recommend that you upgrade your gnuplot5 packages." );
	script_tag( name: "summary", value: "gnuplot5, a command-line driven interactive plotting program, has been
examined with fuzzing by Tim Blazytko, Cornelius Aschermann, Sergej
Schumilo and Nils Bars.
They found various overflow cases which might lead to the execution of
arbitrary code.

  Due to special toolchain hardening in Debian, CVE-2018-19492 is not security relevant, but it is a bug and
  the patch was applied for the sake of completeness. Probably some downstream project does not have the same toolchain settings." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gnuplot5", ver: "5.0.0~rc+dfsg2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gnuplot5-data", ver: "5.0.0~rc+dfsg2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gnuplot5-doc", ver: "5.0.0~rc+dfsg2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gnuplot5-nox", ver: "5.0.0~rc+dfsg2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gnuplot5-qt", ver: "5.0.0~rc+dfsg2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gnuplot5-x11", ver: "5.0.0~rc+dfsg2-1+deb8u1", rls: "DEB8" ) )){
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

