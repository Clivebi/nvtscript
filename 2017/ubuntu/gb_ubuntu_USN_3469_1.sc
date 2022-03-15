if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843358" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-01 05:04:22 +0100 (Wed, 01 Nov 2017)" );
	script_cve_id( "CVE-2017-10911", "CVE-2017-12153", "CVE-2017-12192", "CVE-2017-14051", "CVE-2017-14156", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-14991", "CVE-2017-15537", "CVE-2017-9984", "CVE-2017-9985", "CVE-2017-12154" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-24 10:29:00 +0000 (Fri, 24 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-3469-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Anthony Perard discovered that the Xen
  virtual block driver did not properly initialize some data structures before
  passing them to user space. A local attacker in a guest VM could use this to
  expose sensitive information from the host OS or other guest VMs.
  (CVE-2017-10911) Bo Zhang discovered that the netlink wireless configuration
  interface in the Linux kernel did not properly validate attributes when handling
  certain requests. A local attacker with the CAP_NET_ADMIN could use this to
  cause a denial of service (system crash). (CVE-2017-12153) It was discovered
  that the nested KVM implementation in the Linux kernel in some situations did
  not properly prevent second level guests from reading and writing the hardware
  CR8 register. A local attacker in a guest could use this to cause a denial of
  service (system crash). It was discovered that the key management subsystem in
  the Linux kernel did not properly restrict key reads on negatively instantiated
  keys. A local attacker could use this to cause a denial of service (system
  crash). (CVE-2017-12192) It was discovered that an integer overflow existed in
  the sysfs interface for the QLogic 24xx+ series SCSI driver in the Linux kernel.
  A local privileged attacker could use this to cause a denial of service (system
  crash). (CVE-2017-14051) It was discovered that the ATI Radeon framebuffer
  driver in the Linux kernel did not properly initialize a data structure returned
  to user space. A local attacker could use this to expose sensitive information
  (kernel memory). (CVE-2017-14156) Dave Chinner discovered that the XFS
  filesystem did not enforce that the realtime inode flag was settable only on
  filesystems on a realtime device. A local attacker could use this to cause a
  denial of service (system crash). (CVE-2017-14340) ChunYu Wang discovered that
  the iSCSI transport implementation in the Linux kernel did not properly validate
  data structures. A local attacker could use this to cause a denial of service
  (system crash). (CVE-2017-14489) It was discovered that the generic SCSI driver
  in the Linux kernel did not properly initialize data returned to user space in
  some situations. A local attacker could use this to expose sensitive information
  (kernel memory). (CVE-2017-14991) Dmitry Vyukov discovered that the Floating
  Point Unit (fpu) subsystem in the Linux kernel did not properly handle attempts
  to set reserved bits in a task's extended state (xstate) area. A local attacker
  could use this to cause a denial of service (system crash). (CVE-2017-15537)
  Pengfei Wang discovered that the Turtle Beach MultiSound audio device driver in
  the Linux kernel contained race conditions when fetching from the ring-buffer. A
  local attacker could use this to cause a denial of service (infinite loop).
  (CVE-2017-9984, CVE-2017-9985)" );
	script_tag( name: "affected", value: "linux on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3469-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3469-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1009-kvm", ver: "4.4.0-1009.14", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1033-gke", ver: "4.4.0-1033.33", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1039-aws", ver: "4.4.0-1039.48", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1076-raspi2", ver: "4.4.0-1076.84", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1078-snapdragon", ver: "4.4.0-1078.83", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-98-generic", ver: "4.4.0-98.121", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-98-generic-lpae", ver: "4.4.0-98.121", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-98-lowlatency", ver: "4.4.0-98.121", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-98-powerpc-e500mc", ver: "4.4.0-98.121", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-98-powerpc-smp", ver: "4.4.0-98.121", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-98-powerpc64-emb", ver: "4.4.0-98.121", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-98-powerpc64-smp", ver: "4.4.0-98.121", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-aws", ver: "4.4.0.1039.41", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic", ver: "4.4.0.98.103", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "4.4.0.98.103", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gke", ver: "4.4.0.1033.34", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-kvm", ver: "4.4.0.1009.9", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "4.4.0.98.103", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc", ver: "4.4.0.98.103", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-smp", ver: "4.4.0.98.103", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb", ver: "4.4.0.98.103", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp", ver: "4.4.0.98.103", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-raspi2", ver: "4.4.0.1076.76", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-snapdragon", ver: "4.4.0.1078.70", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

