if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843441" );
	script_version( "2021-06-04T11:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-04 11:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-06 07:54:09 +0100 (Tue, 06 Feb 2018)" );
	script_cve_id( "CVE-2016-2569", "CVE-2016-2570", "CVE-2016-2571", "CVE-2016-3948", "CVE-2018-1000024", "CVE-2018-1000027" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for squid3 USN-3557-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid3'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mathias Fischer discovered that Squid
  incorrectly handled certain long strings in headers. A malicious remote server
  could possibly cause Squid to crash, resulting in a denial of service. This
  issue was only addressed in Ubuntu 16.04 LTS. (CVE-2016-2569) William Lima
  discovered that Squid incorrectly handled XML parsing when processing Edge Side
  Includes (ESI). A malicious remote server could possibly cause Squid to crash,
  resulting in a denial of service. This issue was only addressed in Ubuntu 16.04
  LTS. (CVE-2016-2570) Alex Rousskov discovered that Squid incorrectly handled
  response-parsing failures. A malicious remote server could possibly cause Squid
  to crash, resulting in a denial of service. This issue only applied to Ubuntu
  16.04 LTS. (CVE-2016-2571) Santiago Ruano Rincn discovered that Squid
  incorrectly handled certain Vary headers. A remote attacker could possibly use
  this issue to cause Squid to crash, resulting in a denial of service. This issue
  was only addressed in Ubuntu 16.04 LTS. (CVE-2016-3948) Louis Dion-Marcil
  discovered that Squid incorrectly handled certain Edge Side Includes (ESI)
  responses. A malicious remote server could possibly cause Squid to crash,
  resulting in a denial of service. (CVE-2018-1000024) Louis Dion-Marcil
  discovered that Squid incorrectly handled certain Edge Side Includes (ESI)
  responses. A malicious remote server could possibly cause Squid to crash,
  resulting in a denial of service. (CVE-2018-1000027)" );
	script_tag( name: "affected", value: "squid3 on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3557-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3557-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "squid3", ver: "3.3.8-1ubuntu6.11", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "squid3", ver: "3.5.23-5ubuntu1.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "squid3", ver: "3.5.12-1ubuntu7.5", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

