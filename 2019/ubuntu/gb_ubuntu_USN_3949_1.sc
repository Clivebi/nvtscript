if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843979" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2019-2422" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-04-17 02:00:58 +0000 (Wed, 17 Apr 2019)" );
	script_name( "Ubuntu Update for openjdk-lts USN-3949-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "3949-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3949-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update
  for the 'openjdk-lts' package(s) announced via the USN-3949-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that a memory disclosure
issue existed in the OpenJDK Library subsystem. An attacker could use this to
expose sensitive information and possibly bypass Java sandbox restrictions. (CVE-2019-2422)

Please note that with this update, the OpenJDK package in Ubuntu
18.04 LTS has transitioned from OpenJDK 10 to OpenJDK 11. Several
additional packages were updated to be compatible with OpenJDK 11." );
	script_tag( name: "affected", value: "'openjdk-lts' package(s) on Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk", ver: "11.0.2+9-3ubuntu1~18.04.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre", ver: "11.0.2+9-3ubuntu1~18.04.3", rls: "UBUNTU18.04 LTS" ) )){
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

