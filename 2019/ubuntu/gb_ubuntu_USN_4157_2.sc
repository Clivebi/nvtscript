if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844210" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-15504", "CVE-2019-15505", "CVE-2019-15902", "CVE-2019-16714", "CVE-2019-2181" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-04 05:15:00 +0000 (Wed, 04 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-10-23 02:01:25 +0000 (Wed, 23 Oct 2019)" );
	script_name( "Ubuntu Update for linux-azure USN-4157-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "4157-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-October/005158.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-azure'
  package(s) announced via the USN-4157-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4157-1 fixed vulnerabilities in the Linux kernel for Ubuntu 19.04.
This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 19.04 for Ubuntu
18.04 LTS.

The Marvell Wi-Fi device driver in the Linux
kernel did not properly perform bounds checking, leading to a heap
overflow. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-14814,
CVE-2019-14815, CVE-2019-14816)

Matt Delco discovered that the KVM hypervisor implementation in the Linux
kernel did not properly perform bounds checking when handling coalesced
MMIO write operations. A local attacker with write access to /dev/kvm could
use this to cause a denial of service (system crash). (CVE-2019-14821)

Hui Peng and Mathias Payer discovered that the 91x Wi-Fi driver in the
Linux kernel did not properly handle error conditions on initialization,
leading to a double-free vulnerability. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2019-15504)

It was discovered that the Technisat DVB-S/S2 USB device driver in the
Linux kernel contained a buffer overread. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
expose sensitive information. (CVE-2019-15505)

Brad Spengler discovered that a Spectre mitigation was improperly
implemented in the ptrace subsystem of the Linux kernel. A local attacker
could possibly use this to expose sensitive information. (CVE-2019-15902)

It was discovered that the IPv6 RDS implementation in the Linux kernel did
not properly initialize fields in a data structure returned to user space.
A local attacker could use this to expose sensitive information (kernel
memory). Please note that the RDS protocol is blacklisted in Ubuntu by
default. (CVE-2019-16714)

It was discovered that an integer overflow existed in the Binder
implementation of the Linux kernel, leading to a buffer overflow. A local
attacker could use this to escalate privileges. (CVE-2019-2181)" );
	script_tag( name: "affected", value: "'linux-azure' package(s) on Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1021-gcp", ver: "5.0.0-1021.21~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1023-azure", ver: "5.0.0-1023.24~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1023-gke", ver: "5.0.0-1023.23~18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-32-generic", ver: "5.0.0-32.34~18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-32-generic-lpae", ver: "5.0.0-32.34~18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-32-lowlatency", ver: "5.0.0-32.34~18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-azure", ver: "5.0.0.1023.33", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "5.0.0.1021.26", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-hwe-18.04", ver: "5.0.0.32.89", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae-hwe-18.04", ver: "5.0.0.32.89", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke-5.0", ver: "5.0.0.1023.12", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency-hwe-18.04", ver: "5.0.0.32.89", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-snapdragon-hwe-18.04", ver: "5.0.0.32.89", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual-hwe-18.04", ver: "5.0.0.32.89", rls: "UBUNTU18.04 LTS" ) )){
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

