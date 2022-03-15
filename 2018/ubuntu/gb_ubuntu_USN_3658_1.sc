if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843536" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-24 05:46:04 +0200 (Thu, 24 May 2018)" );
	script_cve_id( "CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-30 13:15:00 +0000 (Tue, 30 Jul 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for procps USN-3658-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'procps'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the procps-ng top utility incorrectly read its
configuration file from the current working directory. A local attacker
could possibly use this issue to escalate privileges. (CVE-2018-1122)

It was discovered that the procps-ng ps tool incorrectly handled memory. A
local user could possibly use this issue to cause a denial of service.
(CVE-2018-1123)

It was discovered that libprocps incorrectly handled the file2strvec()
function. A local attacker could possibly use this to execute arbitrary
code. (CVE-2018-1124)

It was discovered that the procps-ng pgrep utility incorrectly handled
memory. A local attacker could possibly use this issue to cause de denial
of service. (CVE-2018-1125)

It was discovered that procps-ng incorrectly handled memory. A local
attacker could use this issue to cause a denial of service, or possibly
execute arbitrary code. (CVE-2018-1126)" );
	script_tag( name: "affected", value: "procps on Ubuntu 18.04 LTS,
  Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3658-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3658-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|18\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libprocps3", ver: "1:3.3.9-1ubuntu2.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "procps", ver: "1:3.3.9-1ubuntu2.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "libprocps6", ver: "2:3.3.12-1ubuntu2.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "procps", ver: "2:3.3.12-1ubuntu2.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libprocps6", ver: "2:3.3.12-3ubuntu1.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "procps", ver: "2:3.3.12-3ubuntu1.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libprocps4", ver: "2:3.3.10-4ubuntu2.4", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "procps", ver: "2:3.3.10-4ubuntu2.4", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

