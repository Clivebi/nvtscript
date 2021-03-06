if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703812" );
	script_version( "2021-09-10T14:01:42+0000" );
	script_cve_id( "CVE-2017-6903" );
	script_name( "Debian Security Advisory DSA 3812-1 (ioquake3 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-18 00:00:00 +0100 (Sat, 18 Mar 2017)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3812.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "ioquake3 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 1.36+u20140802+gca9eebb-2+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 1.36+u20161101+dfsg1-2.

We recommend that you upgrade your ioquake3 packages." );
	script_tag( name: "summary", value: "It was discovered that ioquake3, a modified version of the ioQuake3 game
engine performs insufficient restrictions on automatically downloaded
content (pk3 files or game code), which allows malicious game servers to
modify configuration settings including driver settings." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ioquake3", ver: "1.36+u20140802+gca9eebb-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ioquake3-dbg", ver: "1.36+u20140802+gca9eebb-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ioquake3-server", ver: "1.36+u20140802+gca9eebb-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

