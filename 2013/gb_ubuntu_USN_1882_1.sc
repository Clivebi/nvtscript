if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841478" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-06-18 10:43:13 +0530 (Tue, 18 Jun 2013)" );
	script_cve_id( "CVE-2013-2850", "CVE-2013-0160", "CVE-2013-2141", "CVE-2013-2146", "CVE-2013-3076", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3230", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3233", "CVE-2013-3234", "CVE-2013-3235" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-1882-1" );
	script_xref( name: "USN", value: "1882-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1882-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-ti-omap4'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.10" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 12.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Kees Cook discovered a flaw in the Linux kernel's iSCSI subsystem. A remote
  unauthenticated attacker could exploit this flaw to cause a denial of
  service (system crash) or potentially gain administrative privileges.
  (CVE-2013-2850)

  An information leak was discovered in the Linux kernel when inotify is used
  to monitor the /dev/ptmx device. A local user could exploit this flaw to
  discover keystroke timing and potentially discover sensitive information
  like password length. (CVE-2013-0160)

  An information leak was discovered in the Linux kernel's tkill and tgkill
  system calls when used from compat processes. A local user could exploit
  this flaw to examine potentially sensitive kernel memory. (CVE-2013-2141)

  A flaw was discovered in the Linux kernel's perf events subsystem for Intel
  Sandy Bridge and Ivy Bridge processors. A local user could exploit this
  flaw to cause a denial of service (system crash). (CVE-2013-2146)

  An information leak was discovered in the Linux kernel's crypto API. A
  local user could exploit this flaw to examine potentially sensitive
  information from the kernel's stack memory. (CVE-2013-3076)

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

  An information leak was discovered in the Linux kernel's CAIF protocol
  implementation. A local user could exploit this flaw to examine potentially
  sensitive information from the kernel's stack memory. (CVE-2013-3227)

  An information leak was discovered in the Linux kernel's IRDA (infrared)
  support subsystem. A local user could exploit this flaw to examine
  potentially sensitive information from the kernel's stack memory.
  (CVE-2013-3228)

  An information leak was discovered i ...

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
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.5.0-226-omap4", ver: "3.5.0-226.39", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

