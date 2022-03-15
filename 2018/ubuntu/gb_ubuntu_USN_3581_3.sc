if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843460" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-23 09:05:45 +0100 (Fri, 23 Feb 2018)" );
	script_cve_id( "CVE-2017-17712", "CVE-2017-15115", "CVE-2017-8824" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-08 18:28:00 +0000 (Wed, 08 May 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-raspi2 USN-3581-3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-raspi2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mohamed Ghannam discovered that the IPv4 raw
  socket implementation in the Linux kernel contained a race condition leading to
  uninitialized pointer usage. A local attacker could use this to cause a denial
  of service or possibly execute arbitrary code. (CVE-2017-17712) ChunYu Wang
  discovered that a use-after-free vulnerability existed in the SCTP protocol
  implementation in the Linux kernel. A local attacker could use this to cause a
  denial of service (system crash) or possibly execute arbitrary code,
  (CVE-2017-15115) Mohamed Ghannam discovered a use-after-free vulnerability in
  the DCCP protocol implementation in the Linux kernel. A local attacker could use
  this to cause a denial of service (system crash) or possibly execute arbitrary
  code. (CVE-2017-8824)" );
	script_tag( name: "affected", value: "linux-raspi2 on Ubuntu 17.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3581-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3581-3/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU17\\.10" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1014-raspi2", ver: "4.13.0-1014.15", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-raspi2", ver: "4.13.0.1014.12", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

