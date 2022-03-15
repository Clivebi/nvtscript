if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843457" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-22 15:56:33 +0100 (Thu, 22 Feb 2018)" );
	script_cve_id( "CVE-2017-17712", "CVE-2017-15115", "CVE-2017-8824", "CVE-2017-5715" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-08 18:28:00 +0000 (Wed, 08 May 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-azure USN-3581-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-azure'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3581-1 fixed vulnerabilities in the
  Linux kernel for Ubuntu 17.10. This update provides the corresponding updates
  for the Linux Hardware Enablement (HWE) kernel from Ubuntu 17.10 for Ubuntu
  16.04 LTS. Mohamed Ghannam discovered that the IPv4 raw socket implementation in
  the Linux kernel contained a race condition leading to uninitialized pointer
  usage. A local attacker could use this to cause a denial of service or possibly
  execute arbitrary code. (CVE-2017-17712) ChunYu Wang discovered that a
  use-after-free vulnerability existed in the SCTP protocol implementation in the
  Linux kernel. A local attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code, (CVE-2017-15115) Mohamed
  Ghannam discovered a use-after-free vulnerability in the DCCP protocol
  implementation in the Linux kernel. A local attacker could use this to cause a
  denial of service (system crash) or possibly execute arbitrary code.
  (CVE-2017-8824) USN-3541-2 mitigated CVE-2017-5715 (Spectre Variant 2) for the
  amd64 architecture in Ubuntu 16.04 LTS. This update provides the compiler-based
  retpoline kernel mitigation for the amd64 and i386 architectures. Original
  advisory details: Jann Horn discovered that microprocessors utilizing
  speculative execution and branch prediction may allow unauthorized memory reads
  via sidechannel attacks. This flaw is known as Spectre. A local attacker could
  use this to expose sensitive information, including kernel memory.
  (CVE-2017-5715)" );
	script_tag( name: "affected", value: "linux-azure on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3581-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3581-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1011-azure", ver: "4.13.0-1011.14", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1011-gcp", ver: "4.13.0-1011.15", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1021-oem", ver: "4.13.0-1021.23", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-36-generic", ver: "4.13.0-36.40~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-36-generic-lpae", ver: "4.13.0-36.40~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-36-lowlatency", ver: "4.13.0-36.40~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-azure", ver: "4.13.0.1011.12", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "4.13.0.1011.13", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-hwe-16.04", ver: "4.13.0.36.55", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-hwe-16.04", ver: "4.13.0.36.55", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gke", ver: "4.13.0.1011.13", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-hwe-16.04", ver: "4.13.0.36.55", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-oem", ver: "4.13.0.1021.25", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

