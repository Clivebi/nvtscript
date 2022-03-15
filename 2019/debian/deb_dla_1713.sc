if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891713" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-7572", "CVE-2019-7573", "CVE-2019-7574", "CVE-2019-7575", "CVE-2019-7576", "CVE-2019-7577", "CVE-2019-7578", "CVE-2019-7635", "CVE-2019-7636", "CVE-2019-7637", "CVE-2019-7638" );
	script_name( "Debian LTS: Security Advisory for libsdl1.2 (DLA-1713-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-14 00:00:00 +0100 (Thu, 14 Mar 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-10 03:15:00 +0000 (Tue, 10 Sep 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00015.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libsdl1.2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.2.15-10+deb8u1.

We recommend that you upgrade your libsdl1.2 packages." );
	script_tag( name: "summary", value: "Multiple buffer overflow security issues have been found in libsdl1.2,
a library that allows low level access to a video frame buffer, audio
output, mouse, and keyboard." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsdl1.2-dbg", ver: "1.2.15-10+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl1.2-dev", ver: "1.2.15-10+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl1.2debian", ver: "1.2.15-10+deb8u1", rls: "DEB8" ) )){
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

