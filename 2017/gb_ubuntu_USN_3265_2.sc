if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843140" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-25 06:33:18 +0200 (Tue, 25 Apr 2017)" );
	script_cve_id( "CVE-2017-7374", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-5669", "CVE-2017-5986", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6347", "CVE-2017-6348" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-24 10:29:00 +0000 (Fri, 24 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-lts-xenial USN-3265-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-xenial'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3265-1 fixed vulnerabilities in the
Linux kernel for Ubuntu 16.04 LTS. This update provides the corresponding updates
for the Linux Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

It was discovered that a use-after-free flaw existed in the filesystem
encryption subsystem in the Linux kernel. A local attacker could use this
to cause a denial of service (system crash). (CVE-2017-7374)

Andrey Konovalov discovered an out-of-bounds access in the IPv6 Generic
Routing Encapsulation (GRE) tunneling implementation in the Linux kernel.
An attacker could use this to possibly expose sensitive information.
(CVE-2017-5897)

Andrey Konovalov discovered that the IPv4 implementation in the Linux
kernel did not properly handle invalid IP options in some situations. An
attacker could use this to cause a denial of service or possibly execute
arbitrary code. (CVE-2017-5970)

Gareth Evans discovered that the shm IPC subsystem in the Linux kernel did
not properly restrict mapping page zero. A local privileged attacker could
use this to execute arbitrary code. (CVE-2017-5669)

Alexander Popov discovered that a race condition existed in the Stream
Control Transmission Protocol (SCTP) implementation in the Linux kernel. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2017-5986)

Dmitry Vyukov discovered that the Linux kernel did not properly handle TCP
packets with the URG flag. A remote attacker could use this to cause a
denial of service. (CVE-2017-6214)

Andrey Konovalov discovered that the LLC subsystem in the Linux kernel did
not properly set up a destructor in certain situations. A local attacker
could use this to cause a denial of service (system crash). (CVE-2017-6345)

It was discovered that a race condition existed in the AF_PACKET handling
code in the Linux kernel. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2017-6346)

Andrey Konovalov discovered that the IP layer in the Linux kernel made
improper assumptions about internal data layout when performing checksums.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2017-6347)

Dmitry Vyukov discovered race conditions in the Infrared (IrDA) subsystem
in the Linux kernel. A local attacker could use this to cause a denial of
service (deadlock). (CVE-2017-6348)" );
	script_tag( name: "affected", value: "linux-lts-xenial on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3265-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3265-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-75-generic", ver: "4.4.0-75.96~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-75-generic-lpae", ver: "4.4.0-75.96~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-75-lowlatency", ver: "4.4.0-75.96~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-75-powerpc-e500mc", ver: "4.4.0-75.96~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-75-powerpc-smp", ver: "4.4.0-75.96~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-75-powerpc64-smp", ver: "4.4.0-75.96~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-lts-xenial", ver: "4.4.0.75.62", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lts-xenial", ver: "4.4.0.75.62", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-lts-xenial", ver: "4.4.0.75.62", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc-lts-xenial", ver: "4.4.0.75.62", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-smp-lts-xenial", ver: "4.4.0.75.62", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp-lts-xenial", ver: "4.4.0.75.62", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

