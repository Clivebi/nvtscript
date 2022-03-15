if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844341" );
	script_version( "2021-07-12T11:00:45+0000" );
	script_cve_id( "CVE-2019-14615", "CVE-2019-16229", "CVE-2019-16232", "CVE-2019-18786", "CVE-2019-18809", "CVE-2019-19057", "CVE-2019-19063", "CVE-2019-19947", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-5108", "CVE-2020-7053" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-12 11:00:45 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-02-19 04:00:35 +0000 (Wed, 19 Feb 2020)" );
	script_name( "Ubuntu: Security Advisory for linux-aws-5.0 (USN-4285-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "4285-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-February/005335.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-aws-5.0'
  package(s) announced via the USN-4285-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Linux kernel did not properly clear data
structures on context switches for certain Intel graphics processors. A
local attacker could use this to expose sensitive information.
(CVE-2019-14615)

It was discovered that the HSA Linux kernel driver for AMD GPU devices did
not properly check for errors in certain situations, leading to a NULL
pointer dereference. A local attacker could possibly use this to cause a
denial of service. (CVE-2019-16229)

It was discovered that the Marvell 8xxx Libertas WLAN device driver in the
Linux kernel did not properly check for errors in certain situations,
leading to a NULL pointer dereference. A local attacker could possibly use
this to cause a denial of service. (CVE-2019-16232)

It was discovered that the Renesas Digital Radio Interface (DRIF) driver in
the Linux kernel did not properly initialize data. A local attacker could
possibly use this to expose sensitive information (kernel memory)
(CVE-2019-18786).

It was discovered that the Afatech AF9005 DVB-T USB device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-18809)

It was discovered that multiple memory leaks existed in the Marvell WiFi-Ex
Driver for the Linux kernel. A local attacker could possibly use this to
cause a denial of service (kernel memory exhaustion). (CVE-2019-19057)

It was discovered that the Realtek rtlwifi USB device driver in the Linux
kernel did not properly deallocate memory in certain error conditions. A
local attacker could possibly use this to cause a denial of service (kernel
memory exhaustion). (CVE-2019-19063)

It was discovered that the Kvaser CAN/USB driver in the Linux kernel did
not properly initialize memory in certain situations. A local attacker
could possibly use this to expose sensitive information (kernel memory).
(CVE-2019-19947)

Gao Chuan discovered that the SAS Class driver in the Linux kernel
contained a race condition that could lead to a NULL pointer dereference. A
local attacker could possibly use this to cause a denial of service (system
crash). (CVE-2019-19965)

It was discovered that the Datagram Congestion Control Protocol (DCCP)
implementation in the Linux kernel did not properly deallocate memory in
certain error conditions. An attacker could possibly use this to cause a
denial of service (kernel memory exhaustion). (CVE-2019-20096)

Mitchell Frank discovered that the Wi-Fi implementation in the Linux kernel
when used as an access point would send IAPP location update ...

  Description truncated. Please see the references for more information." );
	script_tag( name: "affected", value: "'linux-aws-5.0' package(s) on Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1011-oracle", ver: "5.0.0-1011.16", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1025-aws", ver: "5.0.0-1025.28", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1030-gke", ver: "5.0.0-1030.31", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1031-gcp", ver: "5.0.0-1031.32", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1032-azure", ver: "5.0.0-1032.34", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-azure", ver: "5.0.0.1032.43", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "5.0.0.1031.35", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke-5.0", ver: "5.0.0.1030.18", rls: "UBUNTU18.04 LTS" ) )){
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

