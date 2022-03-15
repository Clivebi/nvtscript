if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843314" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-21 07:18:56 +0200 (Thu, 21 Sep 2017)" );
	script_cve_id( "CVE-2017-9375", "CVE-2017-7493", "CVE-2017-8112", "CVE-2017-8380", "CVE-2017-9060", "CVE-2017-9310", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9374", "CVE-2017-9503", "CVE-2017-9524", "CVE-2017-10664", "CVE-2017-10806", "CVE-2017-10911", "CVE-2017-11434", "CVE-2017-12809" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-06 02:06:00 +0000 (Wed, 06 Sep 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for qemu USN-3414-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3414-1 fixed vulnerabilities in QEMU.
  The patch backport for CVE-2017-9375 was incomplete and caused a regression in
  the USB xHCI controller emulation support. This update fixes the problem. We
  apologize for the inconvenience. Original advisory details: Leo Gaspard
  discovered that QEMU incorrectly handled VirtFS access control. A guest attacker
  could use this issue to elevate privileges inside the guest. (CVE-2017-7493) Li
  Qiang discovered that QEMU incorrectly handled VMWare PVSCSI emulation. A
  privileged attacker inside the guest could use this issue to cause QEMU to
  consume resources or crash, resulting in a denial of service. (CVE-2017-8112) It
  was discovered that QEMU incorrectly handled MegaRAID SAS 8708EM2 Host Bus
  Adapter emulation support. A privileged attacker inside the guest could use this
  issue to cause QEMU to crash, resulting in a denial of service, or possibly to
  obtain sensitive host memory. This issue only affected Ubuntu 16.04 LTS and
  Ubuntu 17.04. (CVE-2017-8380) Li Qiang discovered that QEMU incorrectly handled
  the Virtio GPU device. An attacker inside the guest could use this issue to
  cause QEMU to consume resources and crash, resulting in a denial of service.
  This issue only affected Ubuntu 17.04. (CVE-2017-9060) Li Qiang discovered that
  QEMU incorrectly handled the e1000e device. A privileged attacker inside the
  guest could use this issue to cause QEMU to hang, resulting in a denial of
  service. This issue only affected Ubuntu 17.04. (CVE-2017-9310) Li Qiang
  discovered that QEMU incorrectly handled USB OHCI emulation support. An attacker
  inside the guest could use this issue to cause QEMU to crash, resulting in a
  denial of service. (CVE-2017-9330) Li Qiang discovered that QEMU incorrectly
  handled IDE AHCI emulation support. A privileged attacker inside the guest could
  use this issue to cause QEMU to consume resources and crash, resulting in a
  denial of service. (CVE-2017-9373) Li Qiang discovered that QEMU incorrectly
  handled USB EHCI emulation support. A privileged attacker inside the guest could
  use this issue to cause QEMU to consume resources and crash, resulting in a
  denial of service. (CVE-2017-9374) Li Qiang discovered that QEMU incorrectly
  handled USB xHCI emulation support. A privileged attacker inside the guest could
  use this issue to cause QEMU to hang, resulting in a denial of service.
  (CVE-2017-9375) Zhangyanyu discovered that QEMU incorrectly handled MegaRAID SAS
  8708EM2 Host Bus Adapter emulation support. A privileged attacker inside the
  guest could use this issue to cause QEMU to crash, resulting in a denial ...
  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "qemu on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3414-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3414-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "2.0.0+dfsg-2ubuntu1.36", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "2.0.0+dfsg-2ubuntu1.36", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "2.0.0+dfsg-2ubuntu1.36", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "2.0.0+dfsg-2ubuntu1.36", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "2.0.0+dfsg-2ubuntu1.36", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "2.0.0+dfsg-2ubuntu1.36", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "2.0.0+dfsg-2ubuntu1.36", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "2.0.0+dfsg-2ubuntu1.36", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.8+dfsg-3ubuntu2.5", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "1:2.8+dfsg-3ubuntu2.5", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.8+dfsg-3ubuntu2.5", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.8+dfsg-3ubuntu2.5", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.8+dfsg-3ubuntu2.5", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.8+dfsg-3ubuntu2.5", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:2.8+dfsg-3ubuntu2.5", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.8+dfsg-3ubuntu2.5", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.8+dfsg-3ubuntu2.5", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.5+dfsg-5ubuntu10.16", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "1:2.5+dfsg-5ubuntu10.16", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.5+dfsg-5ubuntu10.16", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.5+dfsg-5ubuntu10.16", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.5+dfsg-5ubuntu10.16", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.5+dfsg-5ubuntu10.16", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-s390x", ver: "1:2.5+dfsg-5ubuntu10.16", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.5+dfsg-5ubuntu10.16", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.5+dfsg-5ubuntu10.16", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

