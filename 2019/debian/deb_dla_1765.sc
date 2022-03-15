if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891765" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-11221", "CVE-2019-11222" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-10 18:19:00 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2019-04-26 02:00:09 +0000 (Fri, 26 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for gpac (DLA-1765-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00025.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1765-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gpac'
  package(s) announced via the DLA-1765-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues have been found for gpac, an Open Source multimedia
framework. Using crafted files one can trigger buffer overflow issues
that could be used to crash the application." );
	script_tag( name: "affected", value: "'gpac' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.5.0+svn5324~dfsg1-1+deb8u3.

We recommend that you upgrade your gpac packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gpac", ver: "0.5.0+svn5324~dfsg1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gpac-dbg", ver: "0.5.0+svn5324~dfsg1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gpac-modules-base", ver: "0.5.0+svn5324~dfsg1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgpac-dbg", ver: "0.5.0+svn5324~dfsg1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgpac-dev", ver: "0.5.0+svn5324~dfsg1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgpac3", ver: "0.5.0+svn5324~dfsg1-1+deb8u3", rls: "DEB8" ) )){
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

