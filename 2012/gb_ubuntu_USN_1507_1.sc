if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1507-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841084" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-19 10:44:14 +0530 (Thu, 19 Jul 2012)" );
	script_cve_id( "CVE-2012-1601", "CVE-2012-2744" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "USN", value: "1507-1" );
	script_name( "Ubuntu Update for linux USN-1507-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU8\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1507-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A flaw was found in the Linux kernel's KVM (Kernel Virtual Machine) virtual
  cpu setup. An unprivileged local user could exploit this flaw to crash the
  system leading to a denial of service. (CVE-2012-1601)

  An error was found in the Linux kernel's IPv6 netfilter when connection
  tracking is enabled. A remote attacker could exploit this flaw to crash a
  system if it is using IPv6 with the nf_contrack_ipv6 kernel module loaded.
  (CVE-2012-2744)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-386", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-generic", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-hppa32", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-hppa64", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-itanium", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-lpia", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-lpiacompat", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-mckinley", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-openvz", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-powerpc", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-powerpc-smp", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-powerpc64-smp", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-rt", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-server", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-sparc64", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-sparc64-smp", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-virtual", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.24-32-xen", ver: "2.6.24-32.104", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

