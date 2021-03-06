if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1769-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841364" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-19 09:48:49 +0530 (Tue, 19 Mar 2013)" );
	script_cve_id( "CVE-2013-0190", "CVE-2013-0216", "CVE-2013-0217", "CVE-2013-0231", "CVE-2013-0268", "CVE-2013-0290", "CVE-2013-0311", "CVE-2013-0313", "CVE-2013-0349" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:H/Au:S/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1769-1" );
	script_name( "Ubuntu Update for linux USN-1769-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.10" );
	script_tag( name: "affected", value: "linux on Ubuntu 12.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Andrew Cooper of Citrix reported a Xen stack corruption in the Linux
  kernel. An unprivileged user in a 32bit PVOPS guest can cause the guest
  kernel to crash, or operate erroneously. (CVE-2013-0190)

  A failure to validate input was discovered in the Linux kernel's Xen
  netback (network backend) driver. A user in a guest OS may exploit this
  flaw to cause a denial of service to the guest OS and other guest domains.
  (CVE-2013-0216)

  A memory leak was discovered in the Linux kernel's Xen netback (network
  backend) driver. A user in a guest OS could trigger this flaw to cause a
  denial of service on the system. (CVE-2013-0217)

  A flaw was discovered in the Linux kernel Xen PCI backend driver. If a PCI
  device is assigned to the guest OS, the guest OS could exploit this flaw to
  cause a denial of service on the host. (CVE-2013-0231)

  A flaw was reported in the permission checks done by the Linux kernel for
  /dev/cpu/*/msr. A local root user with all capabilities dropped could
  exploit this flaw to execute code with full root capabilities.
  (CVE-2013-0268)

  Tommi Rantala discovered a flaw in the a flaw the Linux kernels handling of
  datagrams packets when the MSG_PEEK flag is specified. An unprivileged
  local user could exploit this flaw to cause a denial of service (system
  hang). (CVE-2013-0290)

  A flaw was discovered in the Linux kernel's vhost driver used to accelerate
  guest networking in KVM based virtual machines. A privileged guest user
  could exploit this flaw to crash the host system. (CVE-2013-0311)

  A flaw was discovered in the Extended Verification Module (EVM) of the
  Linux kernel. An unprivileged local user code exploit this flaw to cause a
  denial of service (system crash). (CVE-2013-0313)

  An information leak was discovered in the Linux kernel's Bluetooth stack
  when HIDP (Human Interface Device Protocol) support is enabled. A local
  unprivileged user could exploit this flaw to cause an information leak from
  the kernel. (CVE-2013-0349)" );
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
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.5.0-26-generic", ver: "3.5.0-26.42", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.5.0-26-highbank", ver: "3.5.0-26.42", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.5.0-26-omap", ver: "3.5.0-26.42", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.5.0-26-powerpc-smp", ver: "3.5.0-26.42", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.5.0-26-powerpc64-smp", ver: "3.5.0-26.42", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

