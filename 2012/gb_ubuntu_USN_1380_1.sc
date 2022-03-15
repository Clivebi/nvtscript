if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1380-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840913" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-30 19:39:00 +0000 (Thu, 30 Jul 2020)" );
	script_tag( name: "creation_date", value: "2012-03-07 11:19:20 +0530 (Wed, 07 Mar 2012)" );
	script_cve_id( "CVE-2011-2498", "CVE-2011-2518", "CVE-2011-4097", "CVE-2012-0207" );
	script_xref( name: "USN", value: "1380-1" );
	script_name( "Ubuntu Update for linux USN-1380-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1380-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "The linux kernel did not properly account for PTE pages when deciding which
  task to kill in out of memory conditions. A local, unprivileged could
  exploit this flaw to cause a denial of service. (CVE-2011-2498)

  A flaw was discovered in the TOMOYO LSM's handling of mount system calls.
  An unprivileged user could oops the system causing a denial of service.
  (CVE-2011-2518)

  A bug was discovered in the Linux kernel's calculation of OOM (Out of
  memory) scores, that would result in the wrong process being killed. A user
  could use this to kill the process with the highest OOM score, even if that
  process belongs to another user or the system. (CVE-2011-4097)

  A flaw was found in the linux kernels IPv4 IGMP query processing. A remote
  attacker could exploit this to cause a denial of service. (CVE-2012-0207)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-13-generic", ver: "2.6.38-13.56", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-13-generic-pae", ver: "2.6.38-13.56", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-13-omap", ver: "2.6.38-13.56", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-13-powerpc", ver: "2.6.38-13.56", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-13-powerpc-smp", ver: "2.6.38-13.56", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-13-powerpc64-smp", ver: "2.6.38-13.56", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-13-server", ver: "2.6.38-13.56", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-13-versatile", ver: "2.6.38-13.56", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-13-virtual", ver: "2.6.38-13.56", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

