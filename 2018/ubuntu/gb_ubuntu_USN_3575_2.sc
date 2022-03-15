if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843466" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-06 08:39:40 +0100 (Tue, 06 Mar 2018)" );
	script_cve_id( "CVE-2017-11334", "CVE-2017-13672", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15118", "CVE-2017-15119", "CVE-2017-15124", "CVE-2017-15268", "CVE-2017-15289", "CVE-2017-16845", "CVE-2017-17381", "CVE-2017-18043", "CVE-2018-5683" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-31 10:29:00 +0000 (Wed, 31 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for qemu USN-3575-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3575-1 fixed vulnerabilities in QEMU.
  The fix for CVE-2017-11334 caused a regression in Xen environments. This update
  removes the problematic fix pending further investigation. We apologize for the
  inconvenience. Original advisory details: It was discovered that QEMU
  incorrectly handled guest ram. A privileged attacker inside the guest could use
  this issue to cause QEMU to crash, resulting in a denial of service. This issue
  only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2017-11334) David
  Buchanan discovered that QEMU incorrectly handled the VGA device. A privileged
  attacker inside the guest could use this issue to cause QEMU to crash, resulting
  in a denial of service. This issue was only addressed in Ubuntu 17.10.
  (CVE-2017-13672) Thomas Garnier discovered that QEMU incorrectly handled
  multiboot. An attacker could use this issue to cause QEMU to crash, resulting in
  a denial of service, or possibly execute arbitrary code on the host. In the
  default installation, when QEMU is used with libvirt, attackers would be
  isolated by the libvirt AppArmor profile. This issue only affected Ubuntu 14.04
  LTS and Ubuntu 16.04 LTS. (CVE-2017-14167) Tuomas Tynkkynen discovered that QEMU
  incorrectly handled VirtFS directory sharing. An attacker could use this issue
  to obtain sensitive information from host memory. (CVE-2017-15038) Eric Blake
  discovered that QEMU incorrectly handled memory in the NBD server. An attacker
  could use this issue to cause the NBD server to crash, resulting in a denial of
  service. This issue only affected Ubuntu 17.10. (CVE-2017-15118) Eric Blake
  discovered that QEMU incorrectly handled certain options to the NBD server. An
  attacker could use this issue to cause the NBD server to crash, resulting in a
  denial of service. This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04
  LTS. (CVE-2017-15119) Daniel Berrange discovered that QEMU incorrectly handled
  the VNC server. A remote attacker could possibly use this issue to consume
  memory, resulting in a denial of service. This issue was only addressed in
  Ubuntu 17.10. (CVE-2017-15124) Carl Brassey discovered that QEMU incorrectly
  handled certain websockets. A remote attacker could possibly use this issue to
  consume memory, resulting in a denial of service. This issue only affected
  Ubuntu 17.10. (CVE-2017-15268) Guoxiang Niu discovered that QEMU incorrectly
  handled the Cirrus VGA device. A privileged attacker inside the guest could use
  this issue to cause QEMU to crash, resulting in a denial of service.
  (CVE-2017-15289) Cyrille Chatras discovered that QEMU incorrectly handled
  certain PS2 values duri ... Description truncated, for more information please
  check the Reference URL" );
	script_tag( name: "affected", value: "qemu on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3575-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3575-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "qemu", ver: "2.0.0+dfsg-2ubuntu1.40", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "qemu", ver: "1:2.5+dfsg-5ubuntu10.24", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

