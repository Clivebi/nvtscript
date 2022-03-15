if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892357" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-10289" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-31 16:15:00 +0000 (Mon, 31 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-31 03:00:07 +0000 (Mon, 31 Aug 2020)" );
	script_name( "Debian LTS: Security Advisory for ros-actionlib (DLA-2357-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/08/msg00055.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2357-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ros-actionlib'
  package(s) announced via the DLA-2357-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Use of unsafe yaml load was fixed in ros-actionlib,
the Robot OS actionlib library." );
	script_tag( name: "affected", value: "'ros-actionlib' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.11.7-1+deb9u1.

We recommend that you upgrade your ros-actionlib packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cl-actionlib", ver: "1.11.7-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libactionlib-dev", ver: "1.11.7-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libactionlib0d", ver: "1.11.7-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-actionlib", ver: "1.11.7-1+deb9u1", rls: "DEB9" ) )){
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
