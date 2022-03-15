if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704184" );
	script_version( "2021-06-17T11:57:04+0000" );
	script_cve_id( "CVE-2017-12122", "CVE-2017-14440", "CVE-2017-14441", "CVE-2017-14442", "CVE-2017-14448", "CVE-2017-14450", "CVE-2017-2887", "CVE-2018-3837", "CVE-2018-3838", "CVE-2018-3839" );
	script_name( "Debian Security Advisory DSA 4184-1 (sdl-image1.2 - security update)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:57:04 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-28 00:00:00 +0200 (Sat, 28 Apr 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-28 15:42:00 +0000 (Tue, 28 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4184.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "sdl-image1.2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 1.2.12-5+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 1.2.12-5+deb9u1.

We recommend that you upgrade your sdl-image1.2 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/sdl-image1.2" );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in the image loading
library for Simple DirectMedia Layer 1.2, which could result in denial
of service or the execution of arbitrary code if malformed image files
are opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsdl-image1.2", ver: "1.2.12-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl-image1.2-dbg", ver: "1.2.12-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl-image1.2-dev", ver: "1.2.12-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl-image1.2", ver: "1.2.12-5+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl-image1.2-dbg", ver: "1.2.12-5+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl-image1.2-dev", ver: "1.2.12-5+deb9u1", rls: "DEB9" ) )){
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

