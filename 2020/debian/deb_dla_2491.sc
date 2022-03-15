if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892491" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2020-16588", "CVE-2020-16589" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-20 12:09:00 +0000 (Tue, 20 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-12-14 09:20:36 +0000 (Mon, 14 Dec 2020)" );
	script_name( "Debian LTS: Security Advisory for openexr (DLA-2491-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/12/msg00019.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2491-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openexr'
  package(s) announced via the DLA-2491-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two issues were discovered in openexr, a set of tools to manipulate
OpenEXR image files, often in the computer-graphics industry for
visual effects and animation." );
	script_tag( name: "affected", value: "'openexr' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', these problems has been fixed in version
2.2.0-11+deb9u2.

We recommend that you upgrade your openexr packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopenexr-dev", ver: "2.2.0-11+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenexr22", ver: "2.2.0-11+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openexr", ver: "2.2.0-11+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openexr-doc", ver: "2.2.0-11+deb9u2", rls: "DEB9" ) )){
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

