if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844513" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2019-16089", "CVE-2019-19462", "CVE-2019-20810", "CVE-2019-20908", "CVE-2020-10732", "CVE-2020-10757", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-11935", "CVE-2020-13974", "CVE-2020-15780" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-04 23:15:00 +0000 (Mon, 04 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-07-28 03:00:29 +0000 (Tue, 28 Jul 2020)" );
	script_name( "Ubuntu: Security Advisory for linux-azure-5.3 (USN-4440-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "4440-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-July/005533.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-azure-5.3'
  package(s) announced via the USN-4440-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the network block device (nbd) implementation in the
Linux kernel did not properly check for error conditions in some
situations. An attacker could possibly use this to cause a denial of
service (system crash). (CVE-2019-16089)

It was discovered that the kernel->user space relay implementation in the
Linux kernel did not properly check return values in some situations. A
local attacker could possibly use this to cause a denial of service (system
crash). (CVE-2019-19462)

Chuhong Yuan discovered that go7007 USB audio device driver in the Linux
kernel did not properly deallocate memory in some failure conditions. A
physically proximate attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2019-20810)

Jason A. Donenfeld discovered that the ACPI implementation in the Linux
kernel did not properly restrict loading SSDT code from an EFI variable. A
privileged attacker could use this to bypass Secure Boot lockdown
restrictions and execute arbitrary code in the kernel. (CVE-2019-20908)

It was discovered that the elf handling code in the Linux kernel did not
initialize memory before using it in certain situations. A local attacker
could use this to possibly expose sensitive information (kernel memory).
(CVE-2020-10732)

Fan Yang discovered that the mremap implementation in the Linux kernel did
not properly handle DAX Huge Pages. A local attacker with access to DAX
storage could use this to gain administrative privileges. (CVE-2020-10757)

It was discovered that the Linux kernel did not correctly apply Speculative
Store Bypass Disable (SSBD) mitigations in certain situations. A local
attacker could possibly use this to expose sensitive information.
(CVE-2020-10766)

It was discovered that the Linux kernel did not correctly apply Indirect
Branch Predictor Barrier (IBPB) mitigations in certain situations. A local
attacker could possibly use this to expose sensitive information.
(CVE-2020-10767)

It was discovered that the Linux kernel could incorrectly enable indirect
branch speculation after it has been disabled for a process via a prctl()
call. A local attacker could possibly use this to expose sensitive
information. (CVE-2020-10768)

Mauricio Faria de Oliveira discovered that the aufs implementation in the
Linux kernel improperly managed inode reference counts in the
vfsub_dentry_open() method. A local attacker could use this vulnerability
to cause a denial of service. (CVE-2020-11935)

It was discovered that the Virtual Terminal keyboard driver in the Linux
kernel contained an integer overflow. A local attacker could possibly use
this to  ...

  Description truncated. Please see the references for more information." );
	script_tag( name: "affected", value: "'linux-azure-5.3' package(s) on Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-1030-oracle", ver: "5.3.0-1030.32~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-1032-gcp", ver: "5.3.0-1032.34~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-1032-gke", ver: "5.3.0-1032.34~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-1034-azure", ver: "5.3.0-1034.35~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-64-generic", ver: "5.3.0-64.58~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-64-generic-lpae", ver: "5.3.0-64.58~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-64-lowlatency", ver: "5.3.0-64.58~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-azure", ver: "5.3.0.1034.30", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "5.3.0.1032.26", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke-5.3", ver: "5.3.0.1032.17", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gkeop-5.3", ver: "5.3.0.64.120", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oracle", ver: "5.3.0.1030.27", rls: "UBUNTU18.04 LTS" ) )){
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

