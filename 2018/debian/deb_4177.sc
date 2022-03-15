if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704177" );
	script_version( "2021-06-16T02:47:07+0000" );
	script_cve_id( "CVE-2017-12122", "CVE-2017-14440", "CVE-2017-14441", "CVE-2017-14442", "CVE-2017-14448", "CVE-2017-14449", "CVE-2017-14450", "CVE-2017-2887", "CVE-2018-3837", "CVE-2018-3838", "CVE-2018-3839" );
	script_name( "Debian Security Advisory DSA 4177-1 (libsdl2-image - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:47:07 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-20 00:00:00 +0200 (Fri, 20 Apr 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-28 15:42:00 +0000 (Tue, 28 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4177.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "libsdl2-image on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 2.0.0+dfsg-3+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 2.0.1+dfsg-2+deb9u1.

We recommend that you upgrade your libsdl2-image packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/libsdl2-image" );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in the image loading
library for Simple DirectMedia Layer 2, which could result in denial of
service or the execution of arbitrary code if malformed image files are
opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsdl2-image-2.0-0", ver: "2.0.0+dfsg-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl2-image-dbg", ver: "2.0.0+dfsg-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl2-image-dev", ver: "2.0.0+dfsg-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl2-image-2.0-0", ver: "2.0.1+dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl2-image-dbg", ver: "2.0.1+dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl2-image-dev", ver: "2.0.1+dfsg-2+deb9u1", rls: "DEB9" ) )){
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

