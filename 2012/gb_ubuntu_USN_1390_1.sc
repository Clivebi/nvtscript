if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1390-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840918" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-07 11:19:34 +0530 (Wed, 07 Mar 2012)" );
	script_cve_id( "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-2182", "CVE-2011-4324", "CVE-2012-0028" );
	script_xref( name: "USN", value: "1390-1" );
	script_name( "Ubuntu Update for linux USN-1390-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU8\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1390-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Dan Rosenberg reported errors in the OSS (Open Sound System) MIDI
  interface. A local attacker on non-x86 systems might be able to cause a
  denial of service. (CVE-2011-1476)

  Dan Rosenberg reported errors in the kernel's OSS (Open Sound System)
  driver for Yamaha FM synthesizer chips. A local user can exploit this to
  cause memory corruption, causing a denial of service or privilege
  escalation. (CVE-2011-1477)

  Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
  partitions. A local user could exploit this to cause a denial of service or
  escalate privileges. (CVE-2011-2182)

  A flaw was discovered in the Linux kernel's NFSv4 (Network File System
  version 4) file system. A local, unprivileged user could use this flaw to
  cause a denial of service by creating a file in a NFSv4 filesystem.
  (CVE-2011-4324)

  A flaw was found in how the linux kernel handles user-space held futexs. An
  unprivileged user could exploit this flaw to cause a denial of service or
  possibly elevate privileges. (CVE-2012-0028)" );
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
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-386", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-generic", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-hppa32", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-hppa64", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-itanium", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-lpia", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-lpiacompat", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-mckinley", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-openvz", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-powerpc", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-powerpc-smp", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-powerpc64-smp", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-rt", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-server", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-sparc64", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-sparc64-smp", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-virtual", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-31-xen", ver: "2.6.24-31.99", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

