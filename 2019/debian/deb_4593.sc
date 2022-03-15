if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704593" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-12211", "CVE-2019-12213" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-03 05:15:00 +0000 (Sat, 03 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-12-29 03:00:23 +0000 (Sun, 29 Dec 2019)" );
	script_name( "Debian Security Advisory DSA 4593-1 (freeimage - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4593.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4593-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freeimage'
  package(s) announced via the DSA-4593-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was found that freeimage, a graphics library, was affected by the
following two security issues:

CVE-2019-12211
Heap buffer overflow caused by invalid memcpy in PluginTIFF. This
flaw might be leveraged by remote attackers to trigger denial of
service or any other unspecified impact via crafted TIFF data.

CVE-2019-12213
Stack exhaustion caused by unwanted recursion in PluginTIFF. This
flaw might be leveraged by remote attackers to trigger denial of
service via crafted TIFF data." );
	script_tag( name: "affected", value: "'freeimage' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 3.17.0+ds1-5+deb9u1.

For the stable distribution (buster), these problems have been fixed in
version 3.18.0+ds2-1+deb10u1.

We recommend that you upgrade your freeimage packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libfreeimage-dev", ver: "3.18.0+ds2-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreeimage3", ver: "3.18.0+ds2-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreeimageplus-dev", ver: "3.18.0+ds2-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreeimageplus-doc", ver: "3.18.0+ds2-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreeimageplus3", ver: "3.18.0+ds2-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreeimage-dev", ver: "3.17.0+ds1-5+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreeimage3", ver: "3.17.0+ds1-5+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreeimage3-dbg", ver: "3.17.0+ds1-5+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreeimageplus-dev", ver: "3.17.0+ds1-5+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreeimageplus-doc", ver: "3.17.0+ds1-5+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreeimageplus3", ver: "3.17.0+ds1-5+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreeimageplus3-dbg", ver: "3.17.0+ds1-5+deb9u1", rls: "DEB9" ) )){
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

