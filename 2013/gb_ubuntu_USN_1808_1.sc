if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841411" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-06-14 12:50:04 +0530 (Fri, 14 Jun 2013)" );
	script_cve_id( "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6548", "CVE-2013-0228", "CVE-2013-0349", "CVE-2013-1774", "CVE-2013-1796" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:H/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux-ec2 USN-1808-1" );
	script_xref( name: "USN", value: "1808-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1808-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-ec2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "affected", value: "linux-ec2 on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Mathias Krause discovered an information leak in the Linux kernel's
  getsockname implementation for Logical Link Layer (llc) sockets. A local
  user could exploit this flaw to examine some of the kernel's stack memory.
  (CVE-2012-6542)

  Mathias Krause discovered information leaks in the Linux kernel's Bluetooth
  Logical Link Control and Adaptation Protocol (L2CAP) implementation. A
  local user could exploit these flaws to examine some of the kernel's stack
  memory. (CVE-2012-6544)

  Mathias Krause discovered information leaks in the Linux kernel's Bluetooth
  RFCOMM protocol implementation. A local user could exploit these flaws to
  examine parts of kernel memory. (CVE-2012-6545)

  Mathias Krause discovered information leaks in the Linux kernel's
  Asynchronous Transfer Mode (ATM) networking stack. A local user could
  exploit these flaws to examine some parts of kernel memory. (CVE-2012-6546)

  Mathias Krause discovered an information leak in the Linux kernel's UDF
  file system implementation. A local user could exploit this flaw to examine
  some of the kernel's heap memory. (CVE-2012-6548)

  Andrew Jones discovered a flaw with the xen_iret function in Linux kernel's
  Xen virtualizeation. In the 32-bit Xen paravirt platform an unprivileged
  guest OS user could exploit this flaw to cause a denial of service (crash
  the system) or gain guest OS privilege. (CVE-2013-0228)

  An information leak was discovered in the Linux kernel's Bluetooth stack
  when HIDP (Human Interface Device Protocol) support is enabled. A local
  unprivileged user could exploit this flaw to cause an information leak from
  the kernel. (CVE-2013-0349)

  A flaw was discovered in the Edgeort USB serial converter driver when the
  device is disconnected while it is in use. A local user could exploit this
  flaw to cause a denial of service (system crash). (CVE-2013-1774)

  Andrew Honig discovered a flaw in guest OS time updates in the Linux
  kernel's KVM (Kernel-based Virtual Machine). A privileged guest user could
  exploit this flaw to cause a denial of service (crash host system) or
  potential escalate privilege to the host kernel level. (CVE-2013-1796)" );
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
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-351-ec2", ver: "2.6.32-351.64", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

