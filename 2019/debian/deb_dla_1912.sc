if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891912" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-15903" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-15 23:15:00 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-09-07 02:00:21 +0000 (Sat, 07 Sep 2019)" );
	script_name( "Debian LTS: Security Advisory for expat (DLA-1912-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/09/msg00005.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1912-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/939394" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'expat'
  package(s) announced via the DLA-1912-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a heap-based buffer overread
vulnerability in expat, an XML parsing library.

A specially-crafted XML input could fool the parser into changing
from DTD parsing to document parsing too early, a consecutive call to
XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber) then
resulted in a heap-based buffer overread." );
	script_tag( name: "affected", value: "'expat' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in expat version
2.1.0-6+deb8u6.

We recommend that you upgrade your expat packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "expat", ver: "2.1.0-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lib64expat1", ver: "2.1.0-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lib64expat1-dev", ver: "2.1.0-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexpat1", ver: "2.1.0-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexpat1-dev", ver: "2.1.0-6+deb8u6", rls: "DEB8" ) )){
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

