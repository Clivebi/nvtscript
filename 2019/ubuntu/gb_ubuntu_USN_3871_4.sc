if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843892" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2018-10876", "CVE-2018-10879", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10882", "CVE-2018-10880", "CVE-2018-10883", "CVE-2018-14625", "CVE-2018-16882", "CVE-2018-17972", "CVE-2018-18281", "CVE-2018-19407", "CVE-2018-9516" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:36:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-02-05 04:03:33 +0100 (Tue, 05 Feb 2019)" );
	script_name( "Ubuntu Update for linux-aws-hwe USN-3871-4" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "3871-4" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3871-4/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-aws-hwe'
  package(s) announced via the USN-3871-4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-3871-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 18.04 LTS for Ubuntu
16.04 LTS.

Wen Xu discovered that a use-after-free vulnerability existed in the ext4
filesystem implementation in the Linux kernel. An attacker could use this
to construct a malicious ext4 image that, when mounted, could cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2018-10876, CVE-2018-10879)

Wen Xu discovered that a buffer overflow existed in the ext4 filesystem
implementation in the Linux kernel. An attacker could use this to construct
a malicious ext4 image that, when mounted, could cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2018-10877)

Wen Xu discovered that an out-of-bounds write vulnerability existed in the
ext4 filesystem implementation in the Linux kernel. An attacker could use
this to construct a malicious ext4 image that, when mounted, could cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2018-10878, CVE-2018-10882)

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly ensure that xattr information remained in inode
bodies. An attacker could use this to construct a malicious ext4 image
that, when mounted, could cause a denial of service (system crash).
(CVE-2018-10880)

Wen Xu discovered that the ext4 file system implementation in the Linux
kernel could possibly perform an out of bounds write when updating the
journal for an inline file. An attacker could use this to construct a
malicious ext4 image that, when mounted, could cause a denial of service
(system crash). (CVE-2018-10883)

It was discovered that a race condition existed in the vsock address family
implementation of the Linux kernel that could lead to a use-after-free
condition. A local attacker in a guest virtual machine could use this to
expose sensitive information (host machine kernel memory). (CVE-2018-14625)

Cfir Cohen discovered that a use-after-free vulnerability existed in the
KVM implementation of the Linux kernel, when handling interrupts in
environments where nested virtualization is in use (nested KVM
virtualization is not enabled by default in Ubuntu kernels). A local
attacker in a guest VM could possibly use this to gain administrative
privileges in a host machine. (CVE-2018-16882)

Jann Horn discovered that the procfs file system implementation in the
Linux kernel did not properly restrict the ability to inspect the kernel
stack of an arbitrary t ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "linux-aws-hwe on Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.15.0-1027-gcp", ver: "4.15.0-1027.28~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.15.0-1032-aws", ver: "4.15.0-1032.34~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.15.0-45-generic", ver: "4.15.0-45.48~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.15.0-45-generic-lpae", ver: "4.15.0-45.48~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.15.0-45-lowlatency", ver: "4.15.0-45.48~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-aws-hwe", ver: "4.15.0.1032.33", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "4.15.0.1027.41", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-hwe-16.04", ver: "4.15.0.45.66", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-hwe-16.04", ver: "4.15.0.45.66", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gke", ver: "4.15.0.1027.41", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-hwe-16.04", ver: "4.15.0.45.66", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-oem", ver: "4.15.0.45.66", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-virtual-hwe-16.04", ver: "4.15.0.45.66", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

