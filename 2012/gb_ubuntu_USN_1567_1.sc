if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1567-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841147" );
	script_version( "2019-08-06T11:17:21+0000" );
	script_tag( name: "last_modification", value: "2019-08-06 11:17:21 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2012-09-17 16:55:00 +0530 (Mon, 17 Sep 2012)" );
	script_cve_id( "CVE-2012-2745", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-3511" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "USN", value: "1567-1" );
	script_name( "Ubuntu Update for linux USN-1567-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1567-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A flaw was found in how the Linux kernel passed the replacement session
  keyring to a child process. An unprivileged local user could exploit this
  flaw to cause a denial of service (panic). (CVE-2012-2745)

  Ben Hutchings reported a flaw in the Linux kernel with some network drivers
  that support TSO (TCP segment offload). A local or peer user could exploit
  this flaw to cause a denial of service. (CVE-2012-3412)

  Jay Fenlason and Doug Ledford discovered a bug in the Linux kernel
  implementation of RDS sockets. A local unprivileged user could potentially
  use this flaw to read privileged information from the kernel.
  (CVE-2012-3430)

  A flaw was discovered in the madvise feature of the Linux kernel's memory
  subsystem. An unprivileged local use could exploit the flaw to cause a
  denial of service (crash the system). (CVE-2012-3511)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-16-generic", ver: "2.6.38-16.67", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-16-generic-pae", ver: "2.6.38-16.67", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-16-omap", ver: "2.6.38-16.67", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-16-powerpc", ver: "2.6.38-16.67", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-16-powerpc-smp", ver: "2.6.38-16.67", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-16-powerpc64-smp", ver: "2.6.38-16.67", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-16-server", ver: "2.6.38-16.67", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-16-versatile", ver: "2.6.38-16.67", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-16-virtual", ver: "2.6.38-16.67", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

