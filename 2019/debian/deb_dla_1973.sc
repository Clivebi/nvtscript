if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891973" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-18197" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-10-28 03:00:11 +0000 (Mon, 28 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for libxslt (DLA-1973-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00037.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1973-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/942646" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxslt'
  package(s) announced via the DLA-1973-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A security vulnerability was discovered in libxslt, a XSLT 1.0
processing library written in C.

In xsltCopyText in transform.c, a pointer variable is not reset under
certain circumstances. If the relevant memory area happened to be freed
and reused in a certain way, a bounds check could fail and memory
outside a buffer could be written to, or uninitialized data could be
disclosed." );
	script_tag( name: "affected", value: "'libxslt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.1.28-2+deb8u6.

We recommend that you upgrade your libxslt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxslt1-dbg", ver: "1.1.28-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxslt1-dev", ver: "1.1.28-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxslt1.1", ver: "1.1.28-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxslt1", ver: "1.1.28-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxslt1-dbg", ver: "1.1.28-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xsltproc", ver: "1.1.28-2+deb8u6", rls: "DEB8" ) )){
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

