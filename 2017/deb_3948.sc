if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703948" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_cve_id( "CVE-2017-11721" );
	script_name( "Debian Security Advisory DSA 3948-1 (ioquake3 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-19 00:00:00 +0200 (Sat, 19 Aug 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-08 02:29:00 +0000 (Wed, 08 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3948.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "ioquake3 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.36+u20140802+gca9eebb-2+deb8u2.

For the stable distribution (stretch), this problem has been fixed in
version 1.36+u20161101+dfsg1-2+deb9u1.

We recommend that you upgrade your ioquake3 packages." );
	script_tag( name: "summary", value: "A read buffer overflow was discovered in the idtech3 (Quake III Arena)
family of game engines. This allows remote attackers to cause a denial
of service (application crash) or possibly have unspecified other impact
via a crafted packet." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ioquake3", ver: "1.36+u20140802+gca9eebb-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ioquake3-dbg", ver: "1.36+u20140802+gca9eebb-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ioquake3-server", ver: "1.36+u20140802+gca9eebb-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ioquake3", ver: "1.36+u20161101+dfsg1-2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ioquake3-server", ver: "1.36+u20161101+dfsg1-2+deb9u1", rls: "DEB9" ) ) != NULL){
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

