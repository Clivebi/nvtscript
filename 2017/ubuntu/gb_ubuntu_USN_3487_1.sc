if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843376" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-22 07:32:50 +0100 (Wed, 22 Nov 2017)" );
	script_cve_id( "CVE-2017-12188", "CVE-2017-1000255", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-12190", "CVE-2017-12192", "CVE-2017-14156", "CVE-2017-14489", "CVE-2017-14954", "CVE-2017-15265", "CVE-2017-15537", "CVE-2017-15649", "CVE-2017-16525", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16530", "CVE-2017-16531", "CVE-2017-16533", "CVE-2017-16534" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-3487-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the KVM subsystem in
  the Linux kernel did not properly keep track of nested levels in guest page
  tables. A local attacker in a guest VM could use this to cause a denial of
  service (host OS crash) or possibly execute arbitrary code in the host OS.
  (CVE-2017-12188) It was discovered that on the PowerPC architecture, the kernel
  did not properly sanitize the signal stack when handling sigreturn(). A local
  attacker could use this to cause a denial of service (system crash) or possibly
  execute arbitrary code. (CVE-2017-1000255) Bo Zhang discovered that the netlink
  wireless configuration interface in the Linux kernel did not properly validate
  attributes when handling certain requests. A local attacker with the
  CAP_NET_ADMIN could use this to cause a denial of service (system crash).
  (CVE-2017-12153) It was discovered that the nested KVM implementation in the
  Linux kernel in some situations did not properly prevent second level guests
  from reading and writing the hardware CR8 register. A local attacker in a guest
  could use this to cause a denial of service (system crash). (CVE-2017-12154)
  Vitaly Mayatskikh discovered that the SCSI subsystem in the Linux kernel did not
  properly track reference counts when merging buffers. A local attacker could use
  this to cause a denial of service (memory exhaustion). (CVE-2017-12190) It was
  discovered that the key management subsystem in the Linux kernel did not
  properly restrict key reads on negatively instantiated keys. A local attacker
  could use this to cause a denial of service (system crash). (CVE-2017-12192) It
  was discovered that the ATI Radeon framebuffer driver in the Linux kernel did
  not properly initialize a data structure returned to user space. A local
  attacker could use this to expose sensitive information (kernel memory).
  (CVE-2017-14156) ChunYu Wang discovered that the iSCSI transport implementation
  in the Linux kernel did not properly validate data structures. A local attacker
  could use this to cause a denial of service (system crash). (CVE-2017-14489)
  Alexander Potapenko discovered an information leak in the waitid implementation
  of the Linux kernel. A local attacker could use this to expose sensitive
  information (kernel memory). (CVE-2017-14954) It was discovered that a race
  condition existed in the ALSA subsystem of the Linux kernel when creating and
  deleting a port via ioctl(). A local attacker could use this to cause a denial
  of service (system crash) or possibly execute arbitrary code. (CVE-2017-15265)
  Dmitry Vyukov discovered that the Floating Point Unit (fpu) subsystem in the
  Linux kernel did not properly handl ... Description truncated, for more
  information please check the Reference URL" );
	script_tag( name: "affected", value: "linux on Ubuntu 17.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3487-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3487-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1006-raspi2", ver: "4.13.0-1006.6", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-17-generic", ver: "4.13.0-17.20", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-17-generic-lpae", ver: "4.13.0-17.20", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-17-lowlatency", ver: "4.13.0-17.20", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic", ver: "4.13.0.17.18", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "4.13.0.17.18", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "4.13.0.17.18", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-raspi2", ver: "4.13.0.1006.4", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

