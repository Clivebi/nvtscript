if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843132" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-21 06:43:11 +0200 (Fri, 21 Apr 2017)" );
	script_cve_id( "CVE-2016-10028", "CVE-2016-10029", "CVE-2016-10155", "CVE-2016-7907", "CVE-2016-8667", "CVE-2016-8669", "CVE-2016-9381", "CVE-2016-9602", "CVE-2016-9603", "CVE-2016-9776", "CVE-2016-9845", "CVE-2016-9908", "CVE-2016-9846", "CVE-2016-9912", "CVE-2017-5552", "CVE-2017-5578", "CVE-2017-5857", "CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9913", "CVE-2016-9914", "CVE-2016-9915", "CVE-2016-9916", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-2633", "CVE-2017-5525", "CVE-2017-5526", "CVE-2017-5579", "CVE-2017-5667", "CVE-2017-5856", "CVE-2017-5898", "CVE-2017-5973", "CVE-2017-5987", "CVE-2017-6505" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for qemu USN-3261-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Zhenhao Hong discovered that QEMU
incorrectly handled the Virtio GPU device. An attacker inside the guest could use
this issue to cause QEMU to crash, resulting in a denial of service. This issue only
affected Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-10028, CVE-2016-10029)

Li Qiang discovered that QEMU incorrectly handled the 6300esb watchdog. A
privileged attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service. (CVE-2016-10155)

Li Qiang discovered that QEMU incorrectly handled the i.MX Fast Ethernet
Controller. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service. This issue only
affected Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-7907)

It was discovered that QEMU incorrectly handled the JAZZ RC4030 device. A
privileged attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service. (CVE-2016-8667)

It was discovered that QEMU incorrectly handled the 16550A UART device. A
privileged attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service. (CVE-2016-8669)

It was discovered that QEMU incorrectly handled the shared rings when used
with Xen. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service, or possibly execute
arbitrary code on the host. (CVE-2016-9381)

Jann Horn discovered that QEMU incorrectly handled VirtFS directory
sharing. A privileged attacker inside the guest could use this issue to
access files on the host file system outside of the shared directory and
possibly escalate their privileges. In the default installation, when QEMU
is used with libvirt, attackers would be isolated by the libvirt AppArmor
profile. (CVE-2016-9602)

Gerd Hoffmann discovered that QEMU incorrectly handled the Cirrus VGA
device when being used with a VNC connection. A privileged attacker inside
the guest could use this issue to cause QEMU to crash, resulting in a
denial of service, or possibly execute arbitrary code on the host. In the
default installation, when QEMU is used with libvirt, attackers would be
isolated by the libvirt AppArmor profile. (CVE-2016-9603)

It was discovered that QEMU incorrectly handled the ColdFire Fast Ethernet
Controller. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service. (CVE-2016-9776)

Li Qiang discovered that QEMU incorrectly handled the Virtio GPU device. An
attacker inside the guest could use this iss ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "qemu on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3261-1" );
	script_xref( name: "URL", value: "https://www.ubuntu.com/usn/USN-3261-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "2.0.0+dfsg-2ubuntu1.33", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "2.0.0+dfsg-2ubuntu1.33", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "2.0.0+dfsg-2ubuntu1.33", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "2.0.0+dfsg-2ubuntu1.33", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "2.0.0+dfsg-2ubuntu1.33", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "2.0.0+dfsg-2ubuntu1.33", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "2.0.0+dfsg-2ubuntu1.33", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "2.0.0+dfsg-2ubuntu1.33", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.6.1+dfsg-0ubuntu5.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "1:2.6.1+dfsg-0ubuntu5.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.6.1+dfsg-0ubuntu5.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.6.1+dfsg-0ubuntu5.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.6.1+dfsg-0ubuntu5.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.6.1+dfsg-0ubuntu5.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:2.6.1+dfsg-0ubuntu5.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.6.1+dfsg-0ubuntu5.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.6.1+dfsg-0ubuntu5.4", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.5+dfsg-5ubuntu10.11", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "1:2.5+dfsg-5ubuntu10.11", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.5+dfsg-5ubuntu10.11", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.5+dfsg-5ubuntu10.11", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.5+dfsg-5ubuntu10.11", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.5+dfsg-5ubuntu10.11", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:2.5+dfsg-5ubuntu10.11", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.5+dfsg-5ubuntu10.11", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.5+dfsg-5ubuntu10.11", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

