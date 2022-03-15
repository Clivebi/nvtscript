if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892080" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2016-4303" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-28 00:15:00 +0000 (Tue, 28 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-28 04:00:04 +0000 (Tue, 28 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for iperf3 (DLA-2080-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00023.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2080-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/827116" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'iperf3'
  package(s) announced via the DLA-2080-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in iperf3, an Internet Protocol bandwidth
measuring tool.
Bad handling of UTF8/16 strings in an embedded library could cause a
denial of service (crash) or execution of arbitrary code by putting
special characters in a JSON string, which triggers a heap-based buffer
overflow." );
	script_tag( name: "affected", value: "'iperf3' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.0.7-1+deb8u1.

We recommend that you upgrade your iperf3 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "iperf3", ver: "3.0.7-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libiperf-dev", ver: "3.0.7-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libiperf0", ver: "3.0.7-1+deb8u1", rls: "DEB8" ) )){
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

