if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1090-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840615" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-24 14:29:52 +0100 (Thu, 24 Mar 2011)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "USN", value: "1090-1" );
	script_cve_id( "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4158", "CVE-2010-4163", "CVE-2010-4175" );
	script_name( "Ubuntu Update for linux vulnerabilities USN-1090-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1090-1" );
	script_tag( name: "affected", value: "linux vulnerabilities on Ubuntu 10.04 LTS,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Dan Rosenberg discovered that multiple terminal ioctls did not correctly
  initialize structure memory. A local attacker could exploit this to read
  portions of kernel stack memory, leading to a loss of privacy.
  (CVE-2010-4076, CVE-2010-4077)

  Dan Rosenberg discovered that the socket filters did not correctly
  initialize structure memory. A local attacker could create malicious
  filters to read portions of kernel stack memory, leading to a loss of
  privacy. (Ubuntu 10.10 was already fixed in a prior update.) (CVE-2010-4158)

  Dan Rosenberg discovered that the SCSI subsystem did not correctly validate
  iov segments. A local attacker with access to a SCSI device could send
  specially crafted requests to crash the system, leading to a denial of
  service. (CVE-2010-4163)

  Dan Rosenberg discovered that the RDS protocol did not correctly check
  ioctl arguments. A local attacker could exploit this to crash the system,
  leading to a denial of service. (CVE-2010-4175)" );
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
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.35-28-generic-pae", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.35-28-generic", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.35-28-virtual", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-28-generic-pae", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-28-generic", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-28-virtual", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "2.6.35-1028.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-tools-2.6.35-28", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-doc", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.35-28", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-source-2.6.35", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-tools-common", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "block-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "block-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "block-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "char-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "char-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "crypto-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "crypto-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "crypto-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fat-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fat-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fat-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fb-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fb-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fb-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firewire-core-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firewire-core-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "floppy-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "floppy-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "floppy-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-core-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-core-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-core-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-secondary-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-secondary-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-secondary-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "input-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "input-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "irda-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "irda-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "irda-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "kernel-image-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "kernel-image-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "kernel-image-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "md-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "md-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "md-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "message-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "message-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "message-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mouse-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mouse-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mouse-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nfs-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nfs-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-pcmcia-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-pcmcia-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-shared-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-shared-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-shared-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-usb-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-usb-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "parport-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "parport-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "parport-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pata-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pata-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-storage-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-storage-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "plip-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "plip-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ppp-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ppp-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ppp-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "sata-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "sata-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "sata-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "scsi-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "scsi-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "scsi-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "serial-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "serial-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squashfs-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squashfs-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squashfs-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "storage-core-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "storage-core-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "storage-core-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "usb-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "usb-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "virtio-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "virtio-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "virtio-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "vlan-modules-2.6.35-28-generic-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "vlan-modules-2.6.35-28-generic-pae-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "vlan-modules-2.6.35-28-virtual-di", ver: "2.6.35-28.49", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.32-30-386", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.32-30-generic-pae", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.32-30-generic", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-30-386", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-30-generic-pae", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-30-generic", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-30-virtual", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-tools-2.6.32-30", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-doc", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.32-30", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-source-2.6.32", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-tools-common", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "block-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "block-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "char-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "char-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "crypto-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "crypto-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fat-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fat-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fb-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fb-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firewire-core-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firewire-core-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "floppy-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "floppy-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-core-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-core-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-secondary-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fs-secondary-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "input-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "input-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "irda-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "irda-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "kernel-image-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "kernel-image-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "md-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "md-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "message-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "message-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mouse-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mouse-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nfs-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nfs-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-pcmcia-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-pcmcia-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-shared-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-shared-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-usb-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-usb-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "parport-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "parport-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pata-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pata-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-storage-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-storage-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "plip-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "plip-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ppp-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ppp-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "sata-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "sata-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "scsi-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "scsi-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "serial-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "serial-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squashfs-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squashfs-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "storage-core-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "storage-core-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "usb-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "usb-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "virtio-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "virtio-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "vlan-modules-2.6.32-30-generic-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "vlan-modules-2.6.32-30-generic-pae-di", ver: "2.6.32-30.59", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

