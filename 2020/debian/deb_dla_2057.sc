if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892057" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2019-19911", "CVE-2020-5312", "CVE-2020-5313" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-07 03:00:10 +0000 (Tue, 07 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for pillow (DLA-2057-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00003.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2057-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/948224" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pillow'
  package(s) announced via the DLA-2057-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there were three vulnerabilities in Pillow, an
imaging library for the Python programming language:

  * CVE-2019-19911: Prevent a denial-of-service vulnerability caused
by FpxImagePlugin.py calling the range function on an unvalidated
32-bit integer if the number of bands is large.

  * CVE-2020-5312: PCX 'P mode' buffer overflow.

  * CVE-2020-5313: FLI buffer overflow." );
	script_tag( name: "affected", value: "'pillow' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these issues have been fixed in pillow version
2.6.1-2+deb8u4.

We recommend that you upgrade your pillow packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-imaging", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-imaging-tk", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-pil", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-pil-dbg", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-pil-doc", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-pil.imagetk", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-pil.imagetk-dbg", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-sane", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-sane-dbg", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-pil", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-pil-dbg", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-pil.imagetk", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-pil.imagetk-dbg", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-sane", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-sane-dbg", ver: "2.6.1-2+deb8u4", rls: "DEB8" ) )){
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

