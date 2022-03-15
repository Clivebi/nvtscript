if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844551" );
	script_version( "2021-07-12T11:00:45+0000" );
	script_cve_id( "CVE-2019-16091", "CVE-2019-16092", "CVE-2019-16093", "CVE-2019-16094", "CVE-2019-16095" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 11:00:45 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-01 16:15:00 +0000 (Tue, 01 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-02 11:51:15 +0530 (Wed, 02 Sep 2020)" );
	script_name( "Ubuntu: Security Advisory for libmysofa (USN-4473-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "4473-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-August/005577.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmysofa'
  package(s) announced via the USN-4473-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libmysofa incorrectly handled certain input files.
An attacker could possibly use this issue to cause a denial of service or
other unspecified impact.
(CVE-2019-16091, CVE-2019-16092, CVE-2019-16093, CVE-2019-16094,
CVE-2019-16095)" );
	script_tag( name: "affected", value: "'libmysofa' package(s) on Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libmysofa0", ver: "0.6~dfsg0-3+deb10u1build1", rls: "UBUNTU18.04 LTS" ) )){
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

