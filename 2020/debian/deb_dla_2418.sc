if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892418" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_cve_id( "CVE-2017-14245", "CVE-2017-14246", "CVE-2017-14634", "CVE-2017-6892", "CVE-2018-19661", "CVE-2018-19662", "CVE-2018-19758", "CVE-2019-3832" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-29 19:15:00 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-30 04:00:16 +0000 (Fri, 30 Oct 2020)" );
	script_name( "Debian LTS: Security Advisory for libsndfile (DLA-2418-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/10/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2418-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsndfile'
  package(s) announced via the DLA-2418-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues have been found in libsndfile, a library for
reading/writing audio files.
All issues are basically divide by zero errors, heap read overflows or
other buffer overflow errors." );
	script_tag( name: "affected", value: "'libsndfile' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1.0.27-3+deb9u1.

We recommend that you upgrade your libsndfile packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsndfile1", ver: "1.0.27-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsndfile1-dbg", ver: "1.0.27-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsndfile1-dev", ver: "1.0.27-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sndfile-programs", ver: "1.0.27-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sndfile-programs-dbg", ver: "1.0.27-3+deb9u1", rls: "DEB9" ) )){
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

