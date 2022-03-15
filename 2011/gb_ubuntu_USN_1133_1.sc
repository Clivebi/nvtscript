if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1133-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840663" );
	script_version( "2020-08-17T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 08:01:28 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-06-03 09:20:26 +0200 (Fri, 03 Jun 2011)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1133-1" );
	script_cve_id( "CVE-2010-4342", "CVE-2010-4527", "CVE-2010-4529", "CVE-2011-0521", "CVE-2011-0711" );
	script_name( "Ubuntu Update for linux USN-1133-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU8\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1133-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Nelson Elhage discovered that Econet did not correctly handle AUN packets
  over UDP. A local attacker could send specially crafted traffic to crash
  the system, leading to a denial of service. (CVE-2010-4342)

  Dan Rosenberg discovered that the OSS subsystem did not handle name
  termination correctly. A local attacker could exploit this crash the system
  or gain root privileges. (CVE-2010-4527)

  Dan Rosenberg discovered that IRDA did not correctly check the size of
  buffers. On non-x86 systems, a local attacker could exploit this to read
  kernel heap memory, leading to a loss of privacy. (CVE-2010-4529)

  Dan Carpenter discovered that the TTPCI DVB driver did not check certain
  values during an ioctl. If the dvb-ttpci module was loaded, a local
  attacker could exploit this to crash the system, leading to a denial of
  service, or possibly gain root privileges. (CVE-2011-0521)

  Dan Rosenberg discovered that XFS did not correctly initialize memory. A
  local attacker could make crafted ioctl calls to leak portions of kernel
  stack memory, leading to a loss of privacy. (CVE-2011-0711)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-386", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-generic", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-hppa32", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-hppa64", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-itanium", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-lpia", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-lpiacompat", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-mckinley", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-openvz", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-powerpc", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-powerpc-smp", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-powerpc64-smp", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-rt", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-server", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-sparc64", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-sparc64-smp", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-virtual", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-29-xen", ver: "2.6.24-29.89", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

