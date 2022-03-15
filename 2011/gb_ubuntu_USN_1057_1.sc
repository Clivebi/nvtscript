if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1057-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840581" );
	script_version( "2021-05-19T13:27:53+0200" );
	script_tag( name: "last_modification", value: "2021-05-19 13:27:53 +0200 (Wed, 19 May 2021)" );
	script_tag( name: "creation_date", value: "2011-02-04 14:19:53 +0100 (Fri, 04 Feb 2011)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-10 16:09:00 +0000 (Mon, 10 Aug 2020)" );
	script_xref( name: "USN", value: "1057-1" );
	script_cve_id( "CVE-2010-2943", "CVE-2010-3297", "CVE-2010-4072" );
	script_name( "Ubuntu Update for linux-source-2.6.15 vulnerabilities USN-1057-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU6\\.06 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1057-1" );
	script_tag( name: "affected", value: "linux-source-2.6.15 vulnerabilities on Ubuntu 6.06 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Dave Chinner discovered that the XFS filesystem did not correctly order
  inode lookups when exported by NFS. A remote attacker could exploit this to
  read or write disk blocks that had changed file assignment or had become
  unlinked, leading to a loss of privacy. (CVE-2010-2943)

  Dan Rosenberg discovered that several network ioctls did not clear kernel
  memory correctly. A local user could exploit this to read kernel stack
  memory, leading to a loss of privacy. (CVE-2010-3297)

  Kees Cook and Vasiliy Kulikov discovered that the shm interface did not
  clear kernel memory correctly. A local attacker could exploit this to read
  kernel stack memory, leading to a loss of privacy. (CVE-2010-4072)" );
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
if(release == "UBUNTU6.06 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.15-55-386", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.15-55-686", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.15-55-k7", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.15-55-server-bigiron", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.15-55-server", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.15-55", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.15-55-386", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.15-55-686", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.15-55-k7", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.15-55-server-bigiron", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.15-55-server", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-doc-2.6.15", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-kernel-devel", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-source-2.6.15", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "acpi-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "cdrom-core-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "cdrom-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "crc-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ext2-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ext3-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fat-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fb-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firewire-core-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "floppy-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ide-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "input-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ipv6-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "irda-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "jfs-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "kernel-image-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "loop-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "md-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nfs-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-firmware-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-pcmcia-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-shared-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nic-usb-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ntfs-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "parport-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pcmcia-storage-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "plip-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ppp-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "reiserfs-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "sata-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "scsi-core-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "scsi-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "serial-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "socket-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ufs-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "usb-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "usb-storage-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xfs-modules-2.6.15-55-386-di", ver: "2.6.15-55.91", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

