if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842779" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-02 05:21:18 +0200 (Thu, 02 Jun 2016)" );
	script_cve_id( "CVE-2016-2117", "CVE-2015-4004", "CVE-2016-2069", "CVE-2016-2187", "CVE-2016-3672", "CVE-2016-3951", "CVE-2016-3955", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4581" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-2989-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Justin Yackoski discovered that the Atheros
  L2 Ethernet Driver in the Linux kernel incorrectly enables scatter/gather I/O.
  A remote attacker could use this to obtain potentially sensitive information from
  kernel memory. (CVE-2016-2117)

  Jason A. Donenfeld discovered multiple out-of-bounds reads in the OZMO USB
  over wifi device drivers in the Linux kernel. A remote attacker could use
  this to cause a denial of service (system crash) or obtain potentially
  sensitive information from kernel memory. (CVE-2015-4004)

  Andy Lutomirski discovered a race condition in the Linux kernel's
  translation lookaside buffer (TLB) handling of flush events. A local
  attacker could use this to cause a denial of service or possibly leak
  sensitive information. (CVE-2016-2069)

  Ralf Spenneberg discovered that the Linux kernel's GTCO digitizer USB
  device driver did not properly validate endpoint descriptors. An attacker
  with physical access could use this to cause a denial of service (system
  crash). (CVE-2016-2187)

  Hector Marco and Ismael Ripoll discovered that the Linux kernel would
  improperly disable Address Space Layout Randomization (ASLR) for x86
  processes running in 32 bit mode if stack-consumption resource limits were
  disabled. A local attacker could use this to make it easier to exploit an
  existing vulnerability in a setuid/setgid program. (CVE-2016-3672)

  Andrey Konovalov discovered that the CDC Network Control Model USB driver
  in the Linux kernel did not cancel work events queued if a later error
  occurred, resulting in a use-after-free. An attacker with physical access
  could use this to cause a denial of service (system crash). (CVE-2016-3951)

  It was discovered that an out-of-bounds write could occur when handling
  incoming packets in the USB/IP implementation in the Linux kernel. A remote
  attacker could use this to cause a denial of service (system crash) or
  possibly execute arbitrary code. (CVE-2016-3955)

  Kangjie Lu discovered an information leak in the ANSI/IEEE 802.2 LLC type 2
  Support implementations in the Linux kernel. A local attacker could use
  this to obtain potentially sensitive information from kernel memory.
  (CVE-2016-4485)

  Kangjie Lu discovered an information leak in the routing netlink socket
  interface (rtnetlink) implementation in the Linux kernel. A local attacker
  could use this to obtain potentially sensitive information from kernel
  memory. (CVE-2016-4486)

  It was discovered that in some situations the Linux kernel did not handle
  propagated mounts correctly. A local unprivileged attacker could use this
  to cause a denial of service (system crash). (CVE-2016-4581)" );
	script_tag( name: "affected", value: "linux on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2989-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2989-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-87-generic", ver: "3.13.0-87.133", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-87-generic-lpae", ver: "3.13.0-87.133", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-87-lowlatency", ver: "3.13.0-87.133", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-87-powerpc-e500", ver: "3.13.0-87.133", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-87-powerpc-e500mc", ver: "3.13.0-87.133", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-87-powerpc-smp", ver: "3.13.0-87.133", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-87-powerpc64-emb", ver: "3.13.0-87.133", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-87-powerpc64-smp", ver: "3.13.0-87.133", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

