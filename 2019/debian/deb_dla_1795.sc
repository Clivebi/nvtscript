if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891795" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-11473", "CVE-2019-11474", "CVE-2019-11505", "CVE-2019-11506" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-21 02:00:14 +0000 (Tue, 21 May 2019)" );
	script_name( "Debian LTS: Security Advisory for graphicsmagick (DLA-1795-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00027.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1795-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'graphicsmagick'
  package(s) announced via the DLA-1795-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in graphicsmagick, the image
processing toolkit:

CVE-2019-11473

The WriteMATLABImage function (coders/mat.c) is affected by a heap-based
buffer overflow. Remote attackers might leverage this vulnerability to
cause denial of service or any other unspecified impact via crafted Matlab
matrices.

CVE-2019-11474

The WritePDBImage function (coders/pdb.c) is affected by a heap-based
buffer overflow. Remote attackers might leverage this vulnerability to
cause denial of service or any other unspecified impact via a crafted Palm
Database file.

CVE-2019-11505
CVE-2019-11506

The XWD module (coders/xwd.c) is affected by multiple heap-based
buffer overflows and arithmetic exceptions. Remote attackers might leverage
these various flaws to cause denial of service or any other unspecified
impact via crafted XWD files." );
	script_tag( name: "affected", value: "'graphicsmagick' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.3.20-3+deb8u7.

We recommend that you upgrade your graphicsmagick packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick", ver: "1.3.20-3+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-dbg", ver: "1.3.20-3+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-imagemagick-compat", ver: "1.3.20-3+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-libmagick-dev-compat", ver: "1.3.20-3+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphics-magick-perl", ver: "1.3.20-3+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick++1-dev", ver: "1.3.20-3+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick++3", ver: "1.3.20-3+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick1-dev", ver: "1.3.20-3+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick3", ver: "1.3.20-3+deb8u7", rls: "DEB8" ) )){
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

