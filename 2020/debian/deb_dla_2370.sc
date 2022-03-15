if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892370" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2019-20916" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-15 16:18:00 +0000 (Mon, 15 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-09-12 03:00:07 +0000 (Sat, 12 Sep 2020)" );
	script_name( "Debian LTS: Security Advisory for python-pip (DLA-2370-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/09/msg00010.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2370-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-pip'
  package(s) announced via the DLA-2370-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a directory traversal attack in pip,
the Python package installer.

When an URL was given in an install command, as a Content-Disposition
header was permitted to have '../' components in their filename,
arbitrary local files (eg. /root/.ssh/authorized_keys) could be
overridden." );
	script_tag( name: "affected", value: "'python-pip' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
9.0.1-2+deb9u2.

We recommend that you upgrade your python-pip packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-pip", ver: "9.0.1-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-pip-whl", ver: "9.0.1-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-pip", ver: "9.0.1-2+deb9u2", rls: "DEB9" ) )){
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

