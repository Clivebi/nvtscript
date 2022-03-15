if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844767" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2019-14562", "CVE-2019-14584" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-11 16:22:00 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-01-11 10:57:22 +0000 (Mon, 11 Jan 2021)" );
	script_name( "Ubuntu: Security Advisory for edk2 (USN-4684-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "USN", value: "4684-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-January/005827.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'edk2'
  package(s) announced via the USN-4684-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Laszlo Ersek discovered that EDK II incorrectly validated certain signed
images. An attacker could possibly use this issue with a specially crafted
image to cause EDK II to hang, resulting in a denial of service. This issue
only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04 LTS.
(CVE-2019-14562)

It was discovered that EDK II incorrectly parsed signed PKCS #7 data. An
attacker could use this issue to cause EDK II to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2019-14584)" );
	script_tag( name: "affected", value: "'edk2' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "ovmf", ver: "0~20191122.bd85bf54-2ubuntu3.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-efi", ver: "0~20191122.bd85bf54-2ubuntu3.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-efi-aarch64", ver: "0~20191122.bd85bf54-2ubuntu3.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-efi-arm", ver: "0~20191122.bd85bf54-2ubuntu3.1", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "ovmf", ver: "0~20180205.c0d9813c-2ubuntu0.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-efi", ver: "0~20180205.c0d9813c-2ubuntu0.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-efi-aarch64", ver: "0~20180205.c0d9813c-2ubuntu0.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-efi-arm", ver: "0~20180205.c0d9813c-2ubuntu0.3", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "ovmf", ver: "0~20160408.ffea0a2c-2ubuntu0.2", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-efi", ver: "0~20160408.ffea0a2c-2ubuntu0.2", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "ovmf", ver: "2020.05-5ubuntu0.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-efi", ver: "2020.05-5ubuntu0.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-efi-aarch64", ver: "2020.05-5ubuntu0.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-efi-arm", ver: "2020.05-5ubuntu0.1", rls: "UBUNTU20.10" ) )){
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

