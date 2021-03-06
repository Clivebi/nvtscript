if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1514-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841112" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-14 10:40:55 +0530 (Tue, 14 Aug 2012)" );
	script_cve_id( "CVE-2012-2119", "CVE-2012-2136", "CVE-2012-2137", "CVE-2012-2372", "CVE-2012-2373", "CVE-2012-3364", "CVE-2012-3375", "CVE-2012-3400" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1514-1" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-1514-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1514-1" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A flaw was discovered in the Linux kernel's macvtap device driver, which is
  used in KVM (Kernel-based Virtual Machine) to create a network bridge
  between host and guest. A privleged user in a guest could exploit this flaw
  to crash the host, if the vhost_net module is loaded with the
  experimental_zcopytx option enabled. (CVE-2012-2119)

  An error was discovered in the Linux kernel's network TUN/TAP device
  implementation. A local user with access to the TUN/TAP interface (which is
  not available to unprivileged users until granted by a root user) could
  exploit this flaw to crash the system or potential gain administrative
  privileges. (CVE-2012-2136)

  A flaw was found in how the Linux kernel's KVM (Kernel-based Virtual
  Machine) subsystem handled MSI (Message Signaled Interrupts). A local
  unprivileged user could exploit this flaw to cause a denial of service or
  potentially elevate privileges. (CVE-2012-2137)

  A flaw was found in the Linux kernel's Reliable Datagram Sockets (RDS)
  protocol implementation. A local, unprivileged user could use this flaw to
  cause a denial of service. (CVE-2012-2372)

  Ulrich Obergfell discovered an error in the Linux kernel's memory
  management subsystem on 32 bit PAE systems with more than 4GB of memory
  installed. A local unprivileged user could exploit this flaw to crash the
  system. (CVE-2012-2373)

  Dan Rosenberg discovered flaws in the Linux kernel's NCI (Near Field
  Communication Controller Interface). A remote attacker could exploit these
  flaws to crash the system or potentially execute privileged code.
  (CVE-2012-3364)

  A flaw was discovered in the Linux kernel's epoll system call. An
  unprivileged local user could use this flaw to crash the system.
  (CVE-2012-3375)

  Some errors where discovered in the Linux kernel's UDF file system, which
  is used to mount some CD-ROMs and DVDs. An unprivileged local user could
  use these flaws to crash the system. (CVE-2012-3400)" );
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
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-1417-omap4", ver: "3.2.0-1417.23", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

