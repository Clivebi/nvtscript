if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844929" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2021-3489", "CVE-2021-3490", "CVE-2021-3491", "CVE-2020-25639", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-28375", "CVE-2021-29264", "CVE-2021-29265", "CVE-2021-29266", "CVE-2021-29646", "CVE-2021-29650" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-12 03:00:53 +0000 (Wed, 12 May 2021)" );
	script_name( "Ubuntu: Security Advisory for linux (USN-4949-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4949-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-May/006017.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the USN-4949-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ryota Shiga discovered that the eBPF implementation in the Linux kernel did
not properly verify that a BPF program only reserved as much memory for a
ring buffer as was allocated. A local attacker could use this to cause a
denial of service (system crash) or execute arbitrary code. (CVE-2021-3489)

Manfred Paul discovered that the eBPF implementation in the Linux kernel
did not properly track bounds on bitwise operations. A local attacker could
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2021-3490)

Billy Jheng Bing-Jhong discovered that the io_uring implementation of the
Linux kernel did not properly enforce the MAX_RW_COUNT limit in some
situations. A local attacker could use this to cause a denial of service
(system crash) or execute arbitrary code. (CVE-2021-3491)

It was discovered that the Nouveau GPU driver in the Linux kernel did not
properly handle error conditions in some situations. A local attacker could
use this to cause a denial of service (system crash). (CVE-2020-25639)

Olivier Benjamin, Norbert Manthey, Martin Mazein, and Jan H. Schönherr
discovered that the Xen paravirtualization backend in the Linux kernel did
not properly propagate errors to frontend drivers in some situations. An
attacker in a guest VM could possibly use this to cause a denial of service
(host domain crash). (CVE-2021-26930)

Jan Beulich discovered that multiple Xen backends in the Linux kernel did
not properly handle certain error conditions under paravirtualization. An
attacker in a guest VM could possibly use this to cause a denial of service
(host domain crash). (CVE-2021-26931)

It was discovered that the fastrpc driver in the Linux kernel did not
prevent user space applications from sending kernel RPC messages. A local
attacker could possibly use this to gain elevated privileges.
(CVE-2021-28375)

It was discovered that the Freescale Gianfar Ethernet driver for the Linux
kernel did not properly handle receive queue overrun when jumbo frames were
enabled in some situations. An attacker could use this to cause a denial of
service (system crash). (CVE-2021-29264)

It was discovered that the USB/IP driver in the Linux kernel contained race
conditions during the update of local and shared status. An attacker could
use this to cause a denial of service (system crash). (CVE-2021-29265)

It was discovered that the vDPA backend virtio driver in the Linux kernel
contained a use-after-free vulnerability. An attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2021-29266)

It was discovered that th ...

  Description truncated. Please see the references for more information." );
	script_tag( name: "affected", value: "'linux' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS." );
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
report = "";
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-53-generic", ver: "5.8.0-53.60~20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-53-generic-64k", ver: "5.8.0-53.60~20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-53-generic-lpae", ver: "5.8.0-53.60~20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-53-lowlatency", ver: "5.8.0-53.60~20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-64k-hwe-20.04", ver: "5.8.0.53.60~20.04.37", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-hwe-20.04", ver: "5.8.0.53.60~20.04.37", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae-hwe-20.04", ver: "5.8.0.53.60~20.04.37", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency-hwe-20.04", ver: "5.8.0.53.60~20.04.37", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual-hwe-20.04", ver: "5.8.0.53.60~20.04.37", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "UBUNTU20.10"){
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1024-raspi", ver: "5.8.0-1024.27", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1024-raspi-nolpae", ver: "5.8.0-1024.27", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1027-kvm", ver: "5.8.0-1027.29", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1029-oracle", ver: "5.8.0-1029.30", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1031-gcp", ver: "5.8.0-1031.32", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1032-azure", ver: "5.8.0-1032.34", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1033-aws", ver: "5.8.0-1033.35", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-53-generic", ver: "5.8.0-53.60", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-53-generic-64k", ver: "5.8.0-53.60", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-53-generic-lpae", ver: "5.8.0-53.60", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-53-lowlatency", ver: "5.8.0-53.60", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-aws", ver: "5.8.0.1033.35", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-azure", ver: "5.8.0.1032.32", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "5.8.0.1031.31", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic", ver: "5.8.0.53.58", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-64k", ver: "5.8.0.53.58", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "5.8.0.53.58", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke", ver: "5.8.0.1031.31", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-kvm", ver: "5.8.0.1027.29", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "5.8.0.53.58", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oem-20.04", ver: "5.8.0.53.58", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oracle", ver: "5.8.0.1029.28", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-raspi", ver: "5.8.0.1024.27", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-raspi-nolpae", ver: "5.8.0.1024.27", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual", ver: "5.8.0.53.58", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

