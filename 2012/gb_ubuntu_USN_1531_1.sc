if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1531-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841108" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-14 10:40:41 +0530 (Tue, 14 Aug 2012)" );
	script_cve_id( "CVE-2012-2136", "CVE-2012-2372", "CVE-2012-2390" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1531-1" );
	script_name( "Ubuntu Update for linux USN-1531-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1531-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "An error was discovered in the Linux kernel's network TUN/TAP device
  implementation. A local user with access to the TUN/TAP interface (which is
  not available to unprivileged users until granted by a root user) could
  exploit this flaw to crash the system or potential gain administrative
  privileges. (CVE-2012-2136)

  A flaw was found in the Linux kernel's Reliable Datagram Sockets (RDS)
  protocol implementation. A local, unprivileged user could use this flaw to
  cause a denial of service. (CVE-2012-2372)

  An error was discovered in the Linux kernel's memory subsystem (hugetlb).
  An unprivileged local user could exploit this flaw to cause a denial of
  service (crash the system). (CVE-2012-2390)" );
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
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-generic", ver: "2.6.38-15.65", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-generic-pae", ver: "2.6.38-15.65", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-omap", ver: "2.6.38-15.65", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-powerpc", ver: "2.6.38-15.65", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-powerpc-smp", ver: "2.6.38-15.65", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-powerpc64-smp", ver: "2.6.38-15.65", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-server", ver: "2.6.38-15.65", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-versatile", ver: "2.6.38-15.65", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-virtual", ver: "2.6.38-15.65", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

