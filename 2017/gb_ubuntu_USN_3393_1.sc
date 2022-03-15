if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843290" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-18 07:33:56 +0200 (Fri, 18 Aug 2017)" );
	script_cve_id( "CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for clamav USN-3393-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that ClamAV incorrectly
  handled parsing certain e-mail messages. A remote attacker could possibly use
  this issue to cause ClamAV to crash, resulting in a denial of service.
  (CVE-2017-6418) It was discovered that ClamAV incorrectly handled certain
  malformed CHM files. A remote attacker could use this issue to cause ClamAV to
  crash, resulting in a denial of service, or possibly execute arbitrary code.
  This issue only affected Ubuntu 14.04 LTS. In the default installation,
  attackers would be isolated by the ClamAV AppArmor profile. (CVE-2017-6419) It
  was discovered that ClamAV incorrectly handled parsing certain PE files with
  WWPack compression. A remote attacker could possibly use this issue to cause
  ClamAV to crash, resulting in a denial of service. (CVE-2017-6420)" );
	script_tag( name: "affected", value: "clamav on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3393-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3393-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.99.2+addedllvm-0ubuntu0.14.04.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.99.2+dfsg-6ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.99.2+dfsg-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

