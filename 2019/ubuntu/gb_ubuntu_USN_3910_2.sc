if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843934" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2017-18241", "CVE-2018-1120", "CVE-2018-19985", "CVE-2018-7740", "CVE-2019-6133" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-18 15:20:00 +0000 (Mon, 18 Mar 2019)" );
	script_tag( name: "creation_date", value: "2019-03-16 04:08:49 +0100 (Sat, 16 Mar 2019)" );
	script_name( "Ubuntu Update for linux-aws USN-3910-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	script_xref( name: "USN", value: "3910-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-March/004804.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-aws'
  package(s) announced via the USN-3910-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-3910-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

It was discovered that the f2fs filesystem implementation in the Linux
kernel did not handle the noflush_merge mount option correctly. An attacker
could use this to cause a denial of service (system crash).
(CVE-2017-18241)

It was discovered that the procfs filesystem did not properly handle
processes mapping some memory elements onto files. A local attacker could
use this to block utilities that examine the procfs filesystem to report
operating system state, such as ps(1). (CVE-2018-1120)

Hui Peng and Mathias Payer discovered that the Option USB High Speed driver
in the Linux kernel did not properly validate metadata received from the
device. A physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2018-19985)

It was discovered that multiple integer overflows existed in the hugetlbfs
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash). (CVE-2018-7740)

Jann Horn discovered a race condition in the fork() system call in the
Linux kernel. A local attacker could use this to gain access to services
that cache authorizations. (CVE-2019-6133)" );
	script_tag( name: "affected", value: "linux-aws on Ubuntu 14.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1039-aws", ver: "4.4.0-1039.42", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-143-generic", ver: "4.4.0-143.169~14.04.2", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-143-generic-lpae", ver: "4.4.0-143.169~14.04.2", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-143-lowlatency", ver: "4.4.0-143.169~14.04.2", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-143-powerpc-e500mc", ver: "4.4.0-143.169~14.04.2", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-143-powerpc-smp", ver: "4.4.0-143.169~14.04.2", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-143-powerpc64-emb", ver: "4.4.0-143.169~14.04.2", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-143-powerpc64-smp", ver: "4.4.0-143.169~14.04.2", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-aws", ver: "4.4.0.1039.40", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-lts-xenial", ver: "4.4.0.143.125", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lts-xenial", ver: "4.4.0.143.125", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-lts-xenial", ver: "4.4.0.143.125", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc-lts-xenial", ver: "4.4.0.143.125", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-smp-lts-xenial", ver: "4.4.0.143.125", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb-lts-xenial", ver: "4.4.0.143.125", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp-lts-xenial", ver: "4.4.0.143.125", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-virtual-lts-xenial", ver: "4.4.0.143.125", rls: "UBUNTU14.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

