if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843830" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_cve_id( "CVE-2018-10839", "CVE-2018-11806", "CVE-2018-12617", "CVE-2018-16847", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-18849", "CVE-2018-18954", "CVE-2018-19364" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-14 15:00:00 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "creation_date", value: "2018-11-27 15:42:59 +0100 (Tue, 27 Nov 2018)" );
	script_name( "Ubuntu Update for qemu USN-3826-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|18\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3826-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3826-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the USN-3826-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Daniel Shapira and Arash Tohidi discovered that QEMU incorrectly handled
NE2000 device emulation. An attacker inside the guest could use this issue
to cause QEMU to crash, resulting in a denial of service. (CVE-2018-10839)

It was discovered that QEMU incorrectly handled the Slirp networking
back-end. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service, or possibly execute
arbitrary code on the host. In the default installation, when QEMU is used
with libvirt, attackers would be isolated by the libvirt AppArmor profile.
This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu
18.04 LTS. (CVE-2018-11806)

Fakhri Zulkifli discovered that the QEMU guest agent incorrectly handled
certain QMP commands. An attacker could possibly use this issue to crash
the QEMU guest agent, resulting in a denial of service. (CVE-2018-12617)

Li Qiang discovered that QEMU incorrectly handled NVM Express Controller
emulation. An attacker inside the guest could use this issue to cause QEMU
to crash, resulting in a denial of service, or possibly execute arbitrary
code on the host. In the default installation, when QEMU is used with
libvirt, attackers would be isolated by the libvirt AppArmor profile. This
issue only affected Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-16847)

Daniel Shapira and Arash Tohidi discovered that QEMU incorrectly handled
RTL8139 device emulation. An attacker inside the guest could use this issue
to cause QEMU to crash, resulting in a denial of service. (CVE-2018-17958)

Daniel Shapira and Arash Tohidi discovered that QEMU incorrectly handled
PCNET device emulation. An attacker inside the guest could use this issue
to cause QEMU to crash, resulting in a denial of service. (CVE-2018-17962)

Daniel Shapira discovered that QEMU incorrectly handled large packet sizes.
An attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. (CVE-2018-17963)

It was discovered that QEMU incorrectly handled LSI53C895A device
emulation. An attacker inside the guest could use this issue to cause QEMU
to crash, resulting in a denial of service. (CVE-2018-18849)

Moguofang discovered that QEMU incorrectly handled the IPowerNV LPC
controller. An attacker inside the guest could use this issue to cause QEMU
to crash, resulting in a denial of service. This issue only affected Ubuntu
18.04 LTS and Ubuntu 18.10. (CVE-2018-18954)

Zhibin Hu discovered that QEMU incorrectly handled the Plan 9 File System
support. An attacker inside the guest could use this issue to cause QEMU
to crash, resulting in a denial of service. (CVE-2018-19364)" );
	script_tag( name: "affected", value: "qemu on Ubuntu 18.10,
  Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
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
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "2.0.0+dfsg-2ubuntu1.44", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "2.0.0+dfsg-2ubuntu1.44", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "2.0.0+dfsg-2ubuntu1.44", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "2.0.0+dfsg-2ubuntu1.44", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "2.0.0+dfsg-2ubuntu1.44", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "2.0.0+dfsg-2ubuntu1.44", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "2.0.0+dfsg-2ubuntu1.44", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "2.0.0+dfsg-2ubuntu1.44", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.11+dfsg-1ubuntu7.8", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.11+dfsg-1ubuntu7.8", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.11+dfsg-1ubuntu7.8", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.11+dfsg-1ubuntu7.8", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.11+dfsg-1ubuntu7.8", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:2.11+dfsg-1ubuntu7.8", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.11+dfsg-1ubuntu7.8", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.11+dfsg-1ubuntu7.8", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.12+dfsg-3ubuntu8.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.12+dfsg-3ubuntu8.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.12+dfsg-3ubuntu8.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.12+dfsg-3ubuntu8.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.12+dfsg-3ubuntu8.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:2.12+dfsg-3ubuntu8.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.12+dfsg-3ubuntu8.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.12+dfsg-3ubuntu8.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.5+dfsg-5ubuntu10.33", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "1:2.5+dfsg-5ubuntu10.33", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.5+dfsg-5ubuntu10.33", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.5+dfsg-5ubuntu10.33", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.5+dfsg-5ubuntu10.33", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.5+dfsg-5ubuntu10.33", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:2.5+dfsg-5ubuntu10.33", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.5+dfsg-5ubuntu10.33", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.5+dfsg-5ubuntu10.33", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

