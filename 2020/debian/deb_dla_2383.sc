if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892383" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2019-1010057", "CVE-2019-14459" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-26 18:15:00 +0000 (Sat, 26 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-27 03:00:27 +0000 (Sun, 27 Sep 2020)" );
	script_name( "Debian LTS: Security Advisory for nfdump (DLA-2383-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/09/msg00021.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2383-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nfdump'
  package(s) announced via the DLA-2383-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two issues have been found in nfdump, a netflow capture daemon.
Both issues are related to either a buffer overflow or an integer
overflow, which could result in a denial of service or a local code
execution." );
	script_tag( name: "affected", value: "'nfdump' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1.6.15-3+deb9u1.

We recommend that you upgrade your nfdump packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "nfdump", ver: "1.6.15-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nfdump-dbg", ver: "1.6.15-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nfdump-flow-tools", ver: "1.6.15-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nfdump-sflow", ver: "1.6.15-3+deb9u1", rls: "DEB9" ) )){
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

