if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844741" );
	script_version( "2021-07-09T02:00:48+0000" );
	script_cve_id( "CVE-2020-0423", "CVE-2020-10135", "CVE-2020-14351", "CVE-2020-25705", "CVE-2020-27152", "CVE-2020-28915", "CVE-2020-4788" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-09 02:00:48 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-11 00:15:00 +0000 (Fri, 11 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-02 04:00:49 +0000 (Wed, 02 Dec 2020)" );
	script_name( "Ubuntu: Security Advisory for linux (USN-4659-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU20\\.10" );
	script_xref( name: "USN", value: "4659-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-December/005792.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the USN-4659-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that a race condition existed in the binder IPC
implementation in the Linux kernel, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2020-0423)

Daniele Antonioli, Nils Ole Tippenhauer, and Kasper Rasmussen discovered
that legacy pairing and secure-connections pairing authentication in the
Bluetooth protocol could allow an unauthenticated user to complete
authentication without pairing credentials via adjacent access. A
physically proximate attacker could use this to impersonate a previously
paired Bluetooth device. (CVE-2020-10135)

It was discovered that a race condition existed in the perf subsystem of
the Linux kernel, leading to a use-after-free vulnerability. An attacker
with access to the perf subsystem could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2020-14351)

Keyu Man discovered that the ICMP global rate limiter in the Linux kernel
could be used to assist in scanning open UDP ports. A remote attacker could
use to facilitate attacks on UDP based services that depend on source port
randomization. (CVE-2020-25705)

It was discovered that the KVM hypervisor in the Linux kernel did not
properly handle interrupts in certain situations. A local attacker in a
guest VM could possibly use this to cause a denial of service (host system
crash). (CVE-2020-27152)

It was discovered that the framebuffer implementation in the Linux kernel
did not properly perform range checks in certain situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2020-28915)

It was discovered that Power 9 processors could be coerced to expose
information from the L1 cache in certain situations. A local attacker could
use this to expose sensitive information. (CVE-2020-4788)" );
	script_tag( name: "affected", value: "'linux' package(s) on Ubuntu 20.10." );
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
if(release == "UBUNTU20.10"){
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1008-raspi", ver: "5.8.0-1008.11", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1008-raspi-nolpae", ver: "5.8.0-1008.11", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1011-kvm", ver: "5.8.0-1011.12", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1011-oracle", ver: "5.8.0-1011.11", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1012-gcp", ver: "5.8.0-1012.12", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1013-azure", ver: "5.8.0-1013.14", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-1014-aws", ver: "5.8.0-1014.15", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-31-generic", ver: "5.8.0-31.33", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-31-generic-64k", ver: "5.8.0-31.33", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-31-generic-lpae", ver: "5.8.0-31.33", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.8.0-31-lowlatency", ver: "5.8.0-31.33", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-aws", ver: "5.8.0.1014.16", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-azure", ver: "5.8.0.1013.13", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "5.8.0.1012.12", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic", ver: "5.8.0.31.36", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-64k", ver: "5.8.0.31.36", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "5.8.0.31.36", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke", ver: "5.8.0.1012.12", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-kvm", ver: "5.8.0.1011.12", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "5.8.0.31.36", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oem-20.04", ver: "5.8.0.31.36", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oracle", ver: "5.8.0.1011.11", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-raspi", ver: "5.8.0.1008.11", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-raspi-nolpae", ver: "5.8.0.1008.11", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual", ver: "5.8.0.31.36", rls: "UBUNTU20.10" ) )){
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

