if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1081-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840599" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1081-1" );
	script_cve_id( "CVE-2010-3698", "CVE-2010-3865", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4079", "CVE-2010-4083", "CVE-2010-4248", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4527", "CVE-2010-4649", "CVE-2011-1044" );
	script_name( "Ubuntu Update for linux vulnerabilities USN-1081-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1081-1" );
	script_tag( name: "affected", value: "linux vulnerabilities on Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that KVM did not correctly initialize certain CPU
  registers. A local attacker could exploit this to crash the system, leading
  to a denial of service. (CVE-2010-3698)

  Thomas Pollet discovered that the RDS network protocol did not check
  certain iovec buffers. A local attacker could exploit this to crash the
  system or possibly execute arbitrary code as the root user. (CVE-2010-3865)

  Vasiliy Kulikov discovered that the Linux kernel X.25 implementation did
  not correctly clear kernel memory. A local attacker could exploit this to
  read kernel stack memory, leading to a loss of privacy. (CVE-2010-3875)

  Vasiliy Kulikov discovered that the Linux kernel sockets implementation did
  not properly initialize certain structures. A local attacker could exploit
  this to read kernel stack memory, leading to a loss of privacy.
  (CVE-2010-3876)

  Vasiliy Kulikov discovered that the TIPC interface did not correctly
  initialize certain structures. A local attacker could exploit this to read
  kernel stack memory, leading to a loss of privacy. (CVE-2010-3877)

  Nelson Elhage discovered that the Linux kernel IPv4 implementation did not
  properly audit certain bytecodes in netlink messages. A local attacker
  could exploit this to cause the kernel to hang, leading to a denial of
  service. (CVE-2010-3880)

  Dan Rosenberg discovered that the ivtv V4L driver did not correctly
  initialize certain structures. A local attacker could exploit this to read
  kernel stack memory, leading to a loss of privacy. (CVE-2010-4079)

  Dan Rosenberg discovered that the semctl syscall did not correctly clear
  kernel memory. A local attacker could exploit this to read kernel stack
  memory, leading to a loss of privacy. (CVE-2010-4083)

  It was discovered that multithreaded exec did not handle CPU timers
  correctly. A local attacker could exploit this to crash the system, leading
  to a denial of service. (CVE-2010-4248)

  Nelson Elhage discovered that Econet did not correctly handle AUN packets
  over UDP. A local attacker could send specially crafted traffic to crash
  the system, leading to a denial of service. (CVE-2010-4342)

  Tavis Ormandy discovered that the install_special_mapping function could
  bypass the mmap_min_addr restriction. A local attacker could exploit this
  to mmap 4096 bytes below the mmap_min_addr area, possibly improving the
  chances of performing NULL pointer dereference attacks. (CVE-2010-4346)

  Dan Rosenberg discovered that the OSS subsystem did not handle name
  termination correctly. A local attacker could exploit t ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.35-27-generic-pae", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.35-27-generic", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.35-27-virtual", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-27-generic-pae", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-27-generic", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-27-virtual", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "2.6.35-1027.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-tools-2.6.35-27", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-doc", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.35-27", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-source-2.6.35", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-tools-common", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "block-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "block-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "block-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "char-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "char-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "crypto-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "crypto-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "crypto-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fat-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fat-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fat-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fb-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fb-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fb-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firewire-core-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firewire-core-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "floppy-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "floppy-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "floppy-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-core-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-core-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-core-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-secondary-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-secondary-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-secondary-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "input-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "input-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "irda-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "irda-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "irda-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "kernel-image-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "kernel-image-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "kernel-image-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "md-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "md-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "md-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "message-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "message-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "message-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mouse-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mouse-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mouse-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nfs-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nfs-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-pcmcia-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-pcmcia-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-shared-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-shared-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-shared-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-usb-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-usb-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "parport-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "parport-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "parport-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pata-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pata-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-storage-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-storage-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "plip-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "plip-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ppp-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ppp-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ppp-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "sata-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "sata-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "sata-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "scsi-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "scsi-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "scsi-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "serial-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "serial-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squashfs-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squashfs-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squashfs-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "storage-core-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "storage-core-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "storage-core-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "usb-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "usb-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "virtio-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "virtio-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "virtio-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "vlan-modules-2.6.35-27-generic-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "vlan-modules-2.6.35-27-generic-pae-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "vlan-modules-2.6.35-27-virtual-di", ver: "2.6.35-27.48", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

