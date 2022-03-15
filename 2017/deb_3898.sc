if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703898" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_cve_id( "CVE-2016-9063", "CVE-2017-9233" );
	script_name( "Debian Security Advisory DSA 3898-1 (expat - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-25 00:00:00 +0200 (Sun, 25 Jun 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-30 18:31:00 +0000 (Mon, 30 Jul 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3898.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "expat on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 2.1.0-6+deb8u4.

For the stable distribution (stretch), these problems have been fixed in
version 2.2.0-2+deb9u1. For the stable distribution (stretch),
CVE-2016-9063
was already fixed before the initial release.

For the testing distribution (buster), these problems have been fixed
in version 2.2.1-1 or earlier version.

For the unstable distribution (sid), these problems have been fixed in
version 2.2.1-1 or earlier version.

We recommend that you upgrade your expat packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in Expat, an XML parsing C
library. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2016-9063
Gustavo Grieco discovered an integer overflow flaw during parsing of
XML. An attacker can take advantage of this flaw to cause a denial
of service against an application using the Expat library.

CVE-2017-9233
Rhodri James discovered an infinite loop vulnerability within the
entityValueInitProcessor() function while parsing malformed XML
in an external entity. An attacker can take advantage of this
flaw to cause a denial of service against an application using
the Expat library." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "expat", ver: "2.2.0-2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib64expat1", ver: "2.2.0-2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib64expat1-dev", ver: "2.2.0-2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1", ver: "2.2.0-2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1-dev", ver: "2.2.0-2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "expat", ver: "2.1.0-6+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib64expat1", ver: "2.1.0-6+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib64expat1-dev", ver: "2.1.0-6+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1", ver: "2.1.0-6+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1-dev", ver: "2.1.0-6+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1-udeb", ver: "2.1.0-6+deb8u4", rls: "DEB8" ) ) != NULL){
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

