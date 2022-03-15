if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844840" );
	script_version( "2021-08-18T06:00:55+0000" );
	script_cve_id( "CVE-2020-13754" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-18 06:00:55 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-14 20:31:00 +0000 (Mon, 14 Dec 2020)" );
	script_tag( name: "creation_date", value: "2021-02-23 04:00:23 +0000 (Tue, 23 Feb 2021)" );
	script_name( "Ubuntu: Security Advisory for qemu (USN-4467-3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4467-3" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-February/005903.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the USN-4467-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4467-1 fixed vulnerabilities in QEMU. The fix for CVE-2020-13754
introduced a regression in certain environments. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

Ren Ding, Hanqing Zhao, Alexander Bulekov, and Anatoly Trosinenko
discovered that the QEMU incorrectly handled certain msi-x mmio operations.
An attacker inside a guest could possibly use this issue to cause QEMU to
crash, resulting in a denial of service. (CVE-2020-13754)" );
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
	if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:4.2-3ubuntu6.14", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:4.2-3ubuntu6.14", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:4.2-3ubuntu6.14", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:4.2-3ubuntu6.14", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:4.2-3ubuntu6.14", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:4.2-3ubuntu6.14", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:4.2-3ubuntu6.14", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:4.2-3ubuntu6.14", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:4.2-3ubuntu6.14", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86-microvm", ver: "1:4.2-3ubuntu6.14", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86-xen", ver: "1:4.2-3ubuntu6.14", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:2.11+dfsg-1ubuntu7.36", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.11+dfsg-1ubuntu7.36", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.11+dfsg-1ubuntu7.36", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.11+dfsg-1ubuntu7.36", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.11+dfsg-1ubuntu7.36", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.11+dfsg-1ubuntu7.36", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:2.11+dfsg-1ubuntu7.36", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.11+dfsg-1ubuntu7.36", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.11+dfsg-1ubuntu7.36", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:2.5+dfsg-5ubuntu10.51", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.5+dfsg-5ubuntu10.51", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "1:2.5+dfsg-5ubuntu10.51", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.5+dfsg-5ubuntu10.51", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.5+dfsg-5ubuntu10.51", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.5+dfsg-5ubuntu10.51", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.5+dfsg-5ubuntu10.51", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:2.5+dfsg-5ubuntu10.51", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.5+dfsg-5ubuntu10.51", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.5+dfsg-5ubuntu10.51", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:5.0-5ubuntu9.6", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:5.0-5ubuntu9.6", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:5.0-5ubuntu9.6", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:5.0-5ubuntu9.6", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:5.0-5ubuntu9.6", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:5.0-5ubuntu9.6", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:5.0-5ubuntu9.6", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:5.0-5ubuntu9.6", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:5.0-5ubuntu9.6", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86-microvm", ver: "1:5.0-5ubuntu9.6", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86-xen", ver: "1:5.0-5ubuntu9.6", rls: "UBUNTU20.10" ) )){
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

