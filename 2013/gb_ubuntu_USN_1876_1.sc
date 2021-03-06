if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841475" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-06-18 10:41:44 +0530 (Tue, 18 Jun 2013)" );
	script_cve_id( "CVE-2013-1798", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:H/Au:N/C:C/I:N/A:C" );
	script_name( "Ubuntu Update for linux USN-1876-1" );
	script_xref( name: "USN", value: "1876-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1876-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "affected", value: "linux on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Andrew Honig reported a flaw in the way KVM (Kernel-based Virtual Machine)
  emulated the IOAPIC. A privileged guest user could exploit this flaw to
  read host memory or cause a denial of service (crash the host).
  (CVE-2013-1798)

  An information leak was discovered in the Linux kernel's rcvmsg path for
  ATM (Asynchronous Transfer Mode). A local user could exploit this flaw to
  examine potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3222)

  An information leak was discovered in the Linux kernel's recvmsg path for
  ax25 address family. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3223)

  An information leak was discovered in the Linux kernel's recvmsg path for
  the bluetooth address family. A local user could exploit this flaw to
  examine potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3224)

  An information leak was discovered in the Linux kernel's bluetooth rfcomm
  protocol support. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3225)

  An information leak was discovered in the Linux kernel's IRDA (infrared)
  support subsystem. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3228)

  An information leak was discovered in the Linux kernel's s390 - z/VM
  support. A local user could exploit this flaw to examine potentially
  sensitive information from the kernel's stack memory. (CVE-2013-3229)

  An information leak was discovered in the Linux kernel's llc (Logical Link
  Layer 2) support. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3231)

  An information leak was discovered in the Linux kernel's receive message
  handling for the netrom address family. A local user could exploit this
  flaw to obtain sensitive information from the kernel's stack memory.
  (CVE-2013-3232)

  An information leak was discovered in the Linux kernel's Rose X.25 protocol
  layer. A local user could exploit this flaw to examine potentially
  sensitive information from the kernel's stack memory. (CVE-2013-3234)

  An information leak was discovered in the Linux kernel's TIPC (Transparent
  Inter Process Communication) protocol implementation. A local user could
  exploit this flaw to examine potentially sensitive information from the
  kernel's stack memory. (CVE-2013-3235)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-386", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-generic", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-generic-pae", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-ia64", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-lpia", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-powerpc", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-powerpc-smp", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-powerpc64-smp", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-preempt", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-server", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-sparc64", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-sparc64-smp", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-versatile", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-48-virtual", ver: "2.6.32-48.110", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

