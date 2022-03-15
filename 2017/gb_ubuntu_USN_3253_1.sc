if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843124" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-04 06:30:23 +0200 (Tue, 04 Apr 2017)" );
	script_cve_id( "CVE-2013-7108", "CVE-2013-7205", "CVE-2014-1878", "CVE-2016-9566" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-25 11:29:00 +0000 (Tue, 25 Dec 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for nagios3 USN-3253-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nagios3'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Nagios incorrectly
  handled certain long strings. A remote authenticated attacker could use this
  issue to cause Nagios to crash, resulting in a denial of service, or possibly
  obtain sensitive information. (CVE-2013-7108, CVE-2013-7205) It was discovered
  that Nagios incorrectly handled certain long messages to cmd.cgi. A remote
  attacker could possibly use this issue to cause Nagios to crash, resulting in a
  denial of service. (CVE-2014-1878) Dawid Golunski discovered that Nagios
  incorrectly handled symlinks when accessing log files. A local attacker could
  possibly use this issue to elevate privileges. In the default installation of
  Ubuntu, this should be prevented by the Yama link restrictions.
  (CVE-2016-9566)" );
	script_tag( name: "affected", value: "nagios3 on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3253-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3253-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "nagios3-cgi", ver: "3.5.1-1ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nagios3-core", ver: "3.5.1-1ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "nagios3-cgi", ver: "3.5.1.dfsg-2.1ubuntu3.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nagios3-core", ver: "3.5.1.dfsg-2.1ubuntu3.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "nagios3-cgi", ver: "3.5.1.dfsg-2.1ubuntu1.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nagios3-core", ver: "3.5.1.dfsg-2.1ubuntu1.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

