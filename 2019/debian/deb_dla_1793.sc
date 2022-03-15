if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891793" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-11579" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-19 21:29:00 +0000 (Sun, 19 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-20 02:00:10 +0000 (Mon, 20 May 2019)" );
	script_name( "Debian LTS: Security Advisory for dhcpcd5 (DLA-1793-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00024.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1793-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/928104" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dhcpcd5'
  package(s) announced via the DLA-1793-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a read overflow vulnerability in the
dhcpcd5 network management protocol client." );
	script_tag( name: "affected", value: "'dhcpcd5' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in dhcpcd5 version
6.0.5-2+deb8u1.

We recommend that you upgrade your dhcpcd5 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "dhcpcd5", ver: "6.0.5-2+deb8u1", rls: "DEB8" ) )){
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

