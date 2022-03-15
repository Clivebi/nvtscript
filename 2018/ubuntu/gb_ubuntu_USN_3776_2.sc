if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843645" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-02 08:08:40 +0200 (Tue, 02 Oct 2018)" );
	script_cve_id( "CVE-2018-17182", "CVE-2018-15594", "CVE-2018-15572", "CVE-2017-18216", "CVE-2018-10902", "CVE-2018-14633", "CVE-2018-16276", "CVE-2018-6554", "CVE-2018-6555" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-28 18:27:00 +0000 (Fri, 28 Aug 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-aws USN-3776-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-aws'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3776-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

Jann Horn discovered that the vmacache subsystem did not properly handle
sequence number overflows, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or execute arbitrary code. (CVE-2018-17182)

It was discovered that the paravirtualization implementation in the Linux
kernel did not properly handle some indirect calls, reducing the
effectiveness of Spectre v2 mitigations for paravirtual guests. A local
attacker could use this to expose sensitive information. (CVE-2018-15594)

It was discovered that microprocessors utilizing speculative execution and
prediction of return addresses via Return Stack Buffer (RSB) may allow
unauthorized memory reads via sidechannel attacks. An attacker could use
this to expose sensitive information. (CVE-2018-15572)

It was discovered that a NULL pointer dereference could be triggered in the
OCFS2 file system implementation in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2017-18216)

It was discovered that a race condition existed in the raw MIDI driver for
the Linux kernel, leading to a double free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2018-10902)

It was discovered that a stack-based buffer overflow existed in the iSCSI
target implementation of the Linux kernel. A remote attacker could use this
to cause a denial of service (system crash). (CVE-2018-14633)

It was discovered that the YUREX USB device driver for the Linux kernel did
not properly restrict user space reads or writes. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-16276)

It was discovered that a memory leak existed in the IRDA subsystem of the
Linux kernel. A local attacker could use this to cause a denial of service
(kernel memory exhaustion). (CVE-2018-6554)

It was discovered that a use-after-free vulnerability existed in the IRDA
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-6555)" );
	script_tag( name: "affected", value: "linux-aws on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3776-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3776-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1031-aws", ver: "4.4.0-1031.34", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-137-generic", ver: "4.4.0-137.163~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-137-generic-lpae", ver: "4.4.0-137.163~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-137-lowlatency", ver: "4.4.0-137.163~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-137-powerpc-e500mc", ver: "4.4.0-137.163~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-137-powerpc-smp", ver: "4.4.0-137.163~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-137-powerpc64-emb", ver: "4.4.0-137.163~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-137-powerpc64-smp", ver: "4.4.0-137.163~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-aws", ver: "4.4.0.1031.31", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-lts-xenial", ver: "4.4.0.137.117", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lts-xenial", ver: "4.4.0.137.117", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-lts-xenial", ver: "4.4.0.137.117", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc-lts-xenial", ver: "4.4.0.137.117", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-smp-lts-xenial", ver: "4.4.0.137.117", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb-lts-xenial", ver: "4.4.0.137.117", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp-lts-xenial", ver: "4.4.0.137.117", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

