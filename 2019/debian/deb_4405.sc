if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704405" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2017-17480", "CVE-2018-14423", "CVE-2018-18088", "CVE-2018-5785", "CVE-2018-6616" );
	script_name( "Debian Security Advisory DSA 4405-1 (openjpeg2 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-10 00:00:00 +0100 (Sun, 10 Mar 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-03 16:07:00 +0000 (Wed, 03 Feb 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4405.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "openjpeg2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 2.1.2-1.1+deb9u3.

We recommend that you upgrade your openjpeg2 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/openjpeg2" );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in openjpeg2, the
open-source JPEG 2000 codec, that could be leveraged to cause a denial
of service or possibly remote code execution.

CVE-2017-17480
Write stack buffer overflow in the jp3d and jpwl codecs can result
in a denial of service or remote code execution via a crafted jp3d
or jpwl file.

CVE-2018-5785
Integer overflow can result in a denial of service via a crafted bmp
file.

CVE-2018-6616
Excessive iteration can result in a denial of service via a crafted
bmp file.

CVE-2018-14423
Division-by-zero vulnerabilities can result in a denial of service via
a crafted j2k file.

CVE-2018-18088
Null pointer dereference can result in a denial of service via a
crafted bmp file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-7", ver: "2.1.2-1.1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-7-dbg", ver: "2.1.2-1.1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-7-dev", ver: "2.1.2-1.1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-tools", ver: "2.1.2-1.1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp3d-tools", ver: "2.1.2-1.1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp3d7", ver: "2.1.2-1.1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-dec-server", ver: "2.1.2-1.1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-server", ver: "2.1.2-1.1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-viewer", ver: "2.1.2-1.1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip7", ver: "2.1.2-1.1+deb9u3", rls: "DEB9" ) )){
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

