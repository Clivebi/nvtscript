if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892088" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2019-20387" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-30 21:15:00 +0000 (Thu, 30 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-31 04:00:11 +0000 (Fri, 31 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for libsolv (DLA-2088-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00034.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2088-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/949611" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsolv'
  package(s) announced via the DLA-2088-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "repodata_schema2id in repodata.c in libsolv, a dependency solver library,
had a heap-based buffer over-read via a last schema whose length could be
less than the length of the input schema." );
	script_tag( name: "affected", value: "'libsolv' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.6.5-1+deb8u1.

We recommend that you upgrade your libsolv packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsolv-doc", ver: "0.6.5-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolv-perl", ver: "0.6.5-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolv-tools", ver: "0.6.5-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolv0", ver: "0.6.5-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolv0-dbg", ver: "0.6.5-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolv0-dev", ver: "0.6.5-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolvext0", ver: "0.6.5-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolvext0-dbg", ver: "0.6.5-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolvext0-dev", ver: "0.6.5-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-solv", ver: "0.6.5-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-solv", ver: "0.6.5-1+deb8u1", rls: "DEB8" ) )){
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

