if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842708" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-07 05:01:00 +0200 (Thu, 07 Apr 2016)" );
	script_cve_id( "CVE-2015-7833", "CVE-2015-8812", "CVE-2016-2085", "CVE-2016-2383", "CVE-2016-2550", "CVE-2016-2847" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-lts-wily USN-2947-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-wily'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Ralf Spenneberg discovered that the
  usbvision driver in the Linux kernel did not properly sanity check the
  interfaces and endpoints reported by the device. An attacker with physical
  access could cause a denial of service (system crash). (CVE-2015-7833)

  Venkatesh Pottem discovered a use-after-free vulnerability in the Linux
  kernel's CXGB3 driver. A local attacker could use this to cause a denial of
  service (system crash) or possibly execute arbitrary code. (CVE-2015-8812)

  Xiaofei Rex Guo discovered a timing side channel vulnerability in the Linux
  Extended Verification Module (EVM). An attacker could use this to affect
  system integrity. (CVE-2016-2085)

  It was discovered that the extended Berkeley Packet Filter (eBPF)
  implementation in the Linux kernel did not correctly compute branch offsets
  for backward jumps after ctx expansion. A local attacker could use this to
  cause a denial of service (system crash) or possibly execute arbitrary
  code. (CVE-2016-2383)

  David Herrmann discovered that the Linux kernel incorrectly accounted file
  descriptors to the original opener for in-flight file descriptors sent over
  a unix domain socket. A local attacker could use this to cause a denial of
  service (resource exhaustion). (CVE-2016-2550)

  It was discovered that the Linux kernel did not enforce limits on the
  amount of data allocated to buffer pipes. A local attacker could use this
  to cause a denial of service (resource exhaustion). (CVE-2016-2847)" );
	script_tag( name: "affected", value: "linux-lts-wily on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2947-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2947-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-35-generic", ver: "4.2.0-35.40~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-35-generic-lpae", ver: "4.2.0-35.40~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-35-lowlatency", ver: "4.2.0-35.40~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-35-powerpc-e500mc", ver: "4.2.0-35.40~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-35-powerpc-smp", ver: "4.2.0-35.40~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-35-powerpc64-emb", ver: "4.2.0-35.40~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-35-powerpc64-smp", ver: "4.2.0-35.40~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

