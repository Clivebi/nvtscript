if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843009" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-12 05:38:25 +0100 (Thu, 12 Jan 2017)" );
	script_cve_id( "CVE-2016-9756", "CVE-2016-9793", "CVE-2016-9794", "CVE-2016-9806" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-lts-trusty USN-3168-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-trusty'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3168-1 fixed vulnerabilities in the Linux
  kernel for Ubuntu 14.04 LTS. This update provides the corresponding updates for the
  Linux Hardware Enablement (HWE) kernel from Ubuntu 14.04 LTS for Ubuntu
  12.04 LTS.

Dmitry Vyukov discovered that the KVM implementation in the Linux kernel
did not properly initialize the Code Segment (CS) in certain error cases. A
local attacker could use this to expose sensitive information (kernel
memory). (CVE-2016-9756)

Andrey Konovalov discovered that signed integer overflows existed in the
setsockopt() system call when handling the SO_SNDBUFFORCE and
SO_RCVBUFFORCE options. A local attacker with the CAP_NET_ADMIN capability
could use this to cause a denial of service (system crash or memory
corruption). (CVE-2016-9793)

Baozeng Ding discovered a race condition that could lead to a use-after-
free in the Advanced Linux Sound Architecture (ALSA) subsystem of the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash). (CVE-2016-9794)

Baozeng Ding discovered a double free in the netlink_dump() function in the
Linux kernel. A local attacker could use this to cause a denial of service
(system crash). (CVE-2016-9806)" );
	script_tag( name: "affected", value: "linux-lts-trusty on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3168-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3168-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-107-generic", ver: "3.13.0-107.154~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-107-generic-lpae", ver: "3.13.0-107.154~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-lts-trusty", ver: "3.13.0.107.98", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lts-trusty", ver: "3.13.0.107.98", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

