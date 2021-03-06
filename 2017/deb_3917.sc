if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703917" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_cve_id( "CVE-2017-11110" );
	script_name( "Debian Security Advisory DSA 3917-1 (catdoc - security update)" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-23 00:00:00 +0200 (Sun, 23 Jul 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3917.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|10|9)" );
	script_tag( name: "affected", value: "catdoc on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 0.94.4-1.1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1:0.94.3~git20160113.dbc9ec6+dfsg-1+deb9u1.

For the testing distribution (buster), this problem has been fixed
in version 1:0.95-3.

For the unstable distribution (sid), this problem has been fixed in
version 1:0.95-3.

We recommend that you upgrade your catdoc packages." );
	script_tag( name: "summary", value: "A heap-based buffer underflow flaw was discovered in catdoc, a text
extractor for MS-Office files, which may lead to denial of service
(application crash) or have unspecified other impact, if a specially
crafted file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "catdoc", ver: "0.94.4-1.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "catdoc", ver: "1:0.95-3", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "catdoc", ver: "1:0.94.3~git20160113.dbc9ec6+dfsg-1+deb9u1", rls: "DEB9" ) ) != NULL){
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

