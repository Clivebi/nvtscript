if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703768" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_cve_id( "CVE-2016-5159", "CVE-2016-8332", "CVE-2016-9572", "CVE-2016-9573" );
	script_name( "Debian Security Advisory DSA 3768-1 (openjpeg2 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-20 00:00:00 +0100 (Fri, 20 Jan 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3768.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "openjpeg2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 2.1.0-2+deb8u2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your openjpeg2 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities in OpenJPEG,
a JPEG 2000 image compression / decompression library, may result in denial of
service or the execution of arbitrary code if a malformed JPEG 2000 file is
processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libopenjp2-7:amd64", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjp2-7:i386", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjp2-7-dbg:amd64", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjp2-7-dbg:i386", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjp2-7-dev", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjp2-tools", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjp3d-tools", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjp3d7:amd64", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjp3d7:i386", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjpip-dec-server", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjpip-server", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjpip-viewer", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjpip7:amd64", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libopenjpip7:i386", ver: "2.1.0-2+deb8u2", rls: "DEB8" ) ) != NULL){
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

