if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843620" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-19 06:29:00 +0200 (Sun, 19 Aug 2018)" );
	script_cve_id( "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390", "CVE-2018-5391" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-18 16:14:00 +0000 (Fri, 18 Sep 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-3741-3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3741-1 introduced mitigations in the Linux
kernel for Ubuntu 14.04 LTS to address L1 Terminal Fault (L1TF) vulnerabilities
(CVE-2018-3620, CVE-2018-3646). Unfortunately, the update introduced regressions
that caused kernel panics when booting in some environments as well
as preventing Java applications from starting. This update fixes
the problems.

We apologize for the inconvenience.

Original advisory details:

It was discovered that memory present in the L1 data cache of an Intel CPU
core may be exposed to a malicious process that is executing on the CPU
core. This vulnerability is also known as L1 Terminal Fault (L1TF). A local
attacker in a guest virtual machine could use this to expose sensitive
information (memory from other guests or the host OS). (CVE-2018-3646)

It was discovered that memory present in the L1 data cache of an Intel CPU
core may be exposed to a malicious process that is executing on the CPU
core. This vulnerability is also known as L1 Terminal Fault (L1TF). A local
attacker could use this to expose sensitive information (memory from the
kernel or other processes). (CVE-2018-3620)

Juha-Matti Tilli discovered that the TCP implementation in the Linux kernel
performed algorithmically expensive operations in some situations when
handling incoming packets. A remote attacker could use this to cause a
denial of service. (CVE-2018-5390)

Juha-Matti Tilli discovered that the IP implementation in the Linux kernel
performed algorithmically expensive operations in some situations when
handling incoming packet fragments. A remote attacker could use this to
cause a denial of service. (CVE-2018-5391)" );
	script_tag( name: "affected", value: "linux on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3741-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3741-3/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-156-generic", ver: "3.13.0-156.206", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-156-generic-lpae", ver: "3.13.0-156.206", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-156-lowlatency", ver: "3.13.0-156.206", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-156-powerpc-e500", ver: "3.13.0-156.206", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-156-powerpc-e500mc", ver: "3.13.0-156.206", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-156-powerpc-smp", ver: "3.13.0-156.206", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-156-powerpc64-emb", ver: "3.13.0-156.206", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-156-powerpc64-smp", ver: "3.13.0-156.206", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic", ver: "3.13.0.156.166", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "3.13.0.156.166", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "3.13.0.156.166", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500", ver: "3.13.0.156.166", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc", ver: "3.13.0.156.166", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-smp", ver: "3.13.0.156.166", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb", ver: "3.13.0.156.166", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp", ver: "3.13.0.156.166", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

