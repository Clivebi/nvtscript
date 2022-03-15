if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892055" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2018-20349" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-14 03:15:00 +0000 (Wed, 14 Aug 2019)" );
	script_tag( name: "creation_date", value: "2020-01-01 03:00:20 +0000 (Wed, 01 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for igraph (DLA-2055-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/12/msg00038.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2055-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'igraph'
  package(s) announced via the DLA-2055-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in igraph, a library for creating and manipulating
graphs.
A NULL pointer dereference vulneribility was detected in
igraph_i_strdiff()." );
	script_tag( name: "affected", value: "'igraph' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.7.1-2+deb8u1.

We recommend that you upgrade your igraph packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libigraph0", ver: "0.7.1-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libigraph0-dev", ver: "0.7.1-2+deb8u1", rls: "DEB8" ) )){
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

