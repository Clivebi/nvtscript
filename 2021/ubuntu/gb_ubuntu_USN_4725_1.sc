if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844818" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2020-11947", "CVE-2020-15859", "CVE-2020-27821", "CVE-2020-28916", "CVE-2020-29443", "CVE-2021-20181" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-02-09 04:00:43 +0000 (Tue, 09 Feb 2021)" );
	script_name( "Ubuntu: Security Advisory for qemu (USN-4725-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4725-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-February/005880.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the USN-4725-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that QEMU incorrectly handled memory in iSCSI emulation.
An attacker inside the guest could possibly use this issue to obtain
sensitive information. This issue only affected Ubuntu 16.04 LTS, Ubuntu
18.04 LTS, and Ubuntu 20.04 LTS. (CVE-2020-11947)

Alexander Bulekov discovered that QEMU incorrectly handled Intel e1000e
emulation. An attacker inside the guest could use this issue to cause QEMU
to crash, resulting in a denial of service. (CVE-2020-15859)

Alexander Bulekov discovered that QEMU incorrectly handled memory region
cache. An attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service. This issue only affected Ubuntu
20.04 LTS, and Ubuntu 20.10. (CVE-2020-27821)

Cheol-woo Myung discovered that QEMU incorrectly handled Intel e1000e
emulation. An attacker inside the guest could use this issue to cause a
denial of service. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04
LTS, and Ubuntu 20.10. (CVE-2020-28916)

Wenxiang Qian discovered that QEMU incorrectly handled ATAPI emulation. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. (CVE-2020-29443)

It was discovered that QEMU incorrectly handled VirtFS directory sharing.
An attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. (CVE-2021-20181)" );
	script_tag( name: "affected", value: "'qemu' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:4.2-3ubuntu6.12", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:4.2-3ubuntu6.12", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:4.2-3ubuntu6.12", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:4.2-3ubuntu6.12", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:4.2-3ubuntu6.12", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:4.2-3ubuntu6.12", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:4.2-3ubuntu6.12", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:4.2-3ubuntu6.12", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86-microvm", ver: "1:4.2-3ubuntu6.12", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86-xen", ver: "1:4.2-3ubuntu6.12", rls: "UBUNTU20.04 LTS" ) )){
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.11+dfsg-1ubuntu7.35", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.11+dfsg-1ubuntu7.35", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.11+dfsg-1ubuntu7.35", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.11+dfsg-1ubuntu7.35", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.11+dfsg-1ubuntu7.35", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:2.11+dfsg-1ubuntu7.35", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.11+dfsg-1ubuntu7.35", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.11+dfsg-1ubuntu7.35", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.5+dfsg-5ubuntu10.49", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "1:2.5+dfsg-5ubuntu10.49", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.5+dfsg-5ubuntu10.49", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.5+dfsg-5ubuntu10.49", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.5+dfsg-5ubuntu10.49", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.5+dfsg-5ubuntu10.49", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:2.5+dfsg-5ubuntu10.49", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.5+dfsg-5ubuntu10.49", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.5+dfsg-5ubuntu10.49", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:5.0-5ubuntu9.4", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:5.0-5ubuntu9.4", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:5.0-5ubuntu9.4", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:5.0-5ubuntu9.4", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:5.0-5ubuntu9.4", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:5.0-5ubuntu9.4", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:5.0-5ubuntu9.4", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:5.0-5ubuntu9.4", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86-microvm", ver: "1:5.0-5ubuntu9.4", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86-xen", ver: "1:5.0-5ubuntu9.4", rls: "UBUNTU20.10" ) )){
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

