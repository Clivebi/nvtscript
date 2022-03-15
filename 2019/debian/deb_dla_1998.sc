if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891998" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-18874" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-18 21:15:00 +0000 (Mon, 18 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-11-26 12:50:02 +0000 (Tue, 26 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for python-psutil (DLA-1998-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1998-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/944605" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-psutil'
  package(s) announced via the DLA-1998-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there were multiple double free
vulnerabilities in python-psutil, a Python module providing
convenience functions for accessing system process data.

This was caused by incorrect reference counting handling within
for/while loops that convert system data into said Python objects." );
	script_tag( name: "affected", value: "'python-psutil' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in python-psutil
version 2.1.1-1+deb8u1.

We recommend that you upgrade your python-psutil packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-psutil", ver: "2.1.1-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-psutil", ver: "2.1.1-1+deb8u1", rls: "DEB8" ) )){
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

