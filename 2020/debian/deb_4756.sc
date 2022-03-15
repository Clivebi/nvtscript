if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704756" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-17353" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-22 22:15:00 +0000 (Tue, 22 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-08-30 03:00:05 +0000 (Sun, 30 Aug 2020)" );
	script_name( "Debian: Security Advisory for lilypond (DSA-4756-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4756.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4756-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lilypond'
  package(s) announced via the DSA-4756-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Faidon Liambotis discovered that Lilypond, a program for typesetting
sheet music, did not restrict the inclusion of Postscript and SVG
commands when operating in safe mode, which could result in the
execution of arbitrary code when rendering a typesheet file with
embedded Postscript code." );
	script_tag( name: "affected", value: "'lilypond' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 2.19.81+really-2.18.2-13+deb10u1.

We recommend that you upgrade your lilypond packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "lilypond", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-data", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-html", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-html-cs", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-html-de", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-html-es", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-html-fr", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-html-hu", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-html-it", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-html-ja", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-html-nl", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-html-zh", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-pdf", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-pdf-de", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-pdf-es", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-pdf-fr", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-pdf-hu", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-pdf-it", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lilypond-doc-pdf-nl", ver: "2.19.81+really-2.18.2-13+deb10u1", rls: "DEB10" ) )){
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
exit( 0 );

