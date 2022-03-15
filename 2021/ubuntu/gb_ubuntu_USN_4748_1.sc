if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844849" );
	script_version( "2021-08-18T06:00:55+0000" );
	script_cve_id( "CVE-2020-27815", "CVE-2020-29374", "CVE-2020-29568", "CVE-2020-29660", "CVE-2020-29661" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-18 06:00:55 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-09 21:15:00 +0000 (Tue, 09 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-02-26 04:00:56 +0000 (Fri, 26 Feb 2021)" );
	script_name( "Ubuntu: Security Advisory for linux (USN-4748-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "Advisory-ID", value: "USN-4748-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-February/005909.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the USN-4748-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the jfs file system implementation in the Linux
kernel contained an out-of-bounds read vulnerability. A local attacker
could use this to possibly cause a denial of service (system crash).
(CVE-2020-27815)

It was discovered that the memory management subsystem in the Linux kernel
did not properly handle copy-on-write operations in some situations. A
local attacker could possibly use this to gain unintended write access to
read-only memory pages. (CVE-2020-29374)

Michael Kurth and Pawel Wieczorkiewicz discovered that the Xen event
processing backend in the Linux kernel did not properly limit the number of
events queued. An attacker in a guest VM could use this to cause a denial
of service in the host OS. (CVE-2020-29568)

Jann Horn discovered that the tty subsystem of the Linux kernel did not use
consistent locking in some situations, leading to a read-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly expose sensitive information (kernel memory).
(CVE-2020-29660)

Jann Horn discovered a race condition in the tty subsystem of the Linux
kernel in the locking for the TIOCSPGRP ioctl(), leading to a use-after-
free vulnerability. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2020-29661)" );
	script_tag( name: "affected", value: "'linux' package(s) on Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1088-kvm", ver: "4.4.0-1088.97", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1122-aws", ver: "4.4.0-1122.136", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1146-raspi2", ver: "4.4.0-1146.156", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1150-snapdragon", ver: "4.4.0-1150.160", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-203-generic", ver: "4.4.0-203.235", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-203-generic-lpae", ver: "4.4.0-203.235", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-203-lowlatency", ver: "4.4.0-203.235", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-203-powerpc-e500mc", ver: "4.4.0-203.235", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-203-powerpc-smp", ver: "4.4.0-203.235", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-203-powerpc64-emb", ver: "4.4.0-203.235", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-203-powerpc64-smp", ver: "4.4.0-203.235", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-aws", ver: "4.4.0.1122.127", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic", ver: "4.4.0.203.209", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "4.4.0.203.209", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-kvm", ver: "4.4.0.1088.86", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "4.4.0.203.209", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc", ver: "4.4.0.203.209", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc-smp", ver: "4.4.0.203.209", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb", ver: "4.4.0.203.209", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp", ver: "4.4.0.203.209", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-raspi2", ver: "4.4.0.1146.146", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-snapdragon", ver: "4.4.0.1150.142", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual", ver: "4.4.0.203.209", rls: "UBUNTU16.04 LTS" ) )){
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

