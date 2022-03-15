if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844416" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2019-18348", "CVE-2020-8492" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-15 12:15:00 +0000 (Wed, 15 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-05-01 03:00:44 +0000 (Fri, 01 May 2020)" );
	script_name( "Ubuntu: Security Advisory for python3.8 (USN-4333-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU20\\.04 LTS" );
	script_xref( name: "USN", value: "4333-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-April/005416.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3.8'
  package(s) announced via the USN-4333-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4333-1 fixed vulnerabilities in Python. This update provides
the corresponding update for Ubuntu 20.04 LTS.

Original advisory details:

It was discovered that Python incorrectly stripped certain characters from
requests. A remote attacker could use this issue to perform CRLF injection.
(CVE-2019-18348)

It was discovered that Python incorrectly handled certain HTTP requests.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2020-8492)" );
	script_tag( name: "affected", value: "'python3.8' package(s) on Ubuntu 20.04 LTS." );
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "python3.8", ver: "3.8.2-1ubuntu1.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3.8-minimal", ver: "3.8.2-1ubuntu1.1", rls: "UBUNTU20.04 LTS" ) )){
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

