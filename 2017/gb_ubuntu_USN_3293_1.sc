if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843165" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-17 06:52:48 +0200 (Wed, 17 May 2017)" );
	script_cve_id( "CVE-2017-2596", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7477", "CVE-2017-7616" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-3293-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Dmitry Vyukov discovered that KVM
  implementation in the Linux kernel improperly emulated the VMXON instruction. A
  local attacker in a guest OS could use this to cause a denial of service (memory
  consumption) in the host OS. (CVE-2017-2596) Dmitry Vyukov discovered that the
  generic SCSI (sg) subsystem in the Linux kernel contained a stack-based buffer
  overflow. A local attacker with access to an sg device could use this to cause a
  denial of service (system crash) or possibly execute arbitrary code.
  (CVE-2017-7187) It was discovered that a NULL pointer dereference existed in the
  Direct Rendering Manager (DRM) driver for VMWare devices in the Linux kernel. A
  local attacker could use this to cause a denial of service (system crash).
  (CVE-2017-7261) Li Qiang discovered that an integer overflow vulnerability
  existed in the Direct Rendering Manager (DRM) driver for VMWare devices in the
  Linux kernel. A local attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code. (CVE-2017-7294) Jason
  Donenfeld discovered a heap overflow in the MACsec module in the Linux kernel.
  An attacker could use this to cause a denial of service (system crash) or
  possibly execute arbitrary code. (CVE-2017-7477) It was discovered that an
  information leak existed in the set_mempolicy and mbind compat syscalls in the
  Linux kernel. A local attacker could use this to expose sensitive information
  (kernel memory). (CVE-2017-7616)" );
	script_tag( name: "affected", value: "linux on Ubuntu 17.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3293-1" );
	script_xref( name: "URL", value: "https://www.ubuntu.com/usn/usn-3293-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU17\\.04" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-1005-raspi2", ver: "4.10.0-1005.7", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-21-generic", ver: "4.10.0-21.23", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-21-generic-lpae", ver: "4.10.0-21.23", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-21-lowlatency", ver: "4.10.0-21.23", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic", ver: "4.10.0.21.23", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "4.10.0.21.23", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "4.10.0.21.23", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-raspi2", ver: "4.10.0.1005.7", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

