if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844781" );
	script_version( "2021-08-20T06:00:57+0000" );
	script_cve_id( "CVE-2018-18873", "CVE-2018-19542", "CVE-2020-27828", "CVE-2017-9782" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 06:00:57 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-03 04:15:00 +0000 (Wed, 03 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-01-12 04:00:25 +0000 (Tue, 12 Jan 2021)" );
	script_name( "Ubuntu: Security Advisory for jasper (USN-4688-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4688-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-January/005831.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jasper'
  package(s) announced via the USN-4688-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Jasper incorrectly certain files.
An attacker could possibly use this issue to cause a crash.
(CVE-2018-18873)

It was discovered that Jasper incorrectly handled certain files.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2018-19542)

It was discovered that Jasper incorrectly handled certain JPC encoders.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2020-27828)

It was discovered that Jasper incorrectly handled certain images.
An attacker could possibly use this issue to expose sensitive information
or cause a crash.
(CVE-2017-9782)" );
	script_tag( name: "affected", value: "'jasper' package(s) on Ubuntu 16.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libjasper1", ver: "1.900.1-debian1-2.4ubuntu1.3", rls: "UBUNTU16.04 LTS" ) )){
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
}
exit( 0 );

