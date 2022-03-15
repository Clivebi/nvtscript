if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843535" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-23 05:41:11 +0200 (Wed, 23 May 2018)" );
	script_cve_id( "CVE-2017-17975", "CVE-2017-18193", "CVE-2017-18222", "CVE-2018-1065", "CVE-2018-1068", "CVE-2018-1130", "CVE-2018-5803", "CVE-2018-7480", "CVE-2018-7757", "CVE-2018-7995", "CVE-2018-8781", "CVE-2018-8822" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-14 23:29:00 +0000 (Tue, 14 May 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-raspi2 USN-3656-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-raspi2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Tuba Yavuz discovered that a double-free error existed in the USBTV007
driver of the Linux kernel. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2017-17975)

It was discovered that a race condition existed in the F2FS implementation
in the Linux kernel. A local attacker could use this to cause a denial of
service (system crash). (CVE-2017-18193)

It was discovered that a buffer overflow existed in the Hisilicon HNS
Ethernet Device driver in the Linux kernel. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-18222)

It was discovered that the netfilter subsystem in the Linux kernel did not
validate that rules containing jumps contained user-defined chains. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-1065)

It was discovered that the netfilter subsystem of the Linux kernel did not
properly validate ebtables offsets. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-1068)

It was discovered that a null pointer dereference vulnerability existed in
the DCCP protocol implementation in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash). (CVE-2018-1130)

It was discovered that the SCTP Protocol implementation in the Linux kernel
did not properly validate userspace provided payload lengths in some
situations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2018-5803)

It was discovered that a double free error existed in the block layer
subsystem of the Linux kernel when setting up a request queue. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-7480)

It was discovered that a memory leak existed in the SAS driver subsystem of
the Linux kernel. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2018-7757)

It was discovered that a race condition existed in the x86 machine check
handler in the Linux kernel. A local privileged attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-7995)

Eyal Itkin discovered that the USB displaylink video adapter driver in the
Linux kernel did not properly validate mmap offsets sent from userspace. A
local attacker could use this to expose sensitive information (kernel
memory) or possibly execute arbitrary code. (CVE-2018-8781)

Si ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "linux-raspi2 on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3656-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3656-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1090-raspi2", ver: "4.4.0-1090.98", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1093-snapdragon", ver: "4.4.0-1093.98", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-raspi2", ver: "4.4.0.1090.90", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-snapdragon", ver: "4.4.0.1093.85", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

