if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844987" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2021-3609", "CVE-2021-3600", "CVE-2021-23133" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-23 02:15:00 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-24 03:00:50 +0000 (Thu, 24 Jun 2021)" );
	script_name( "Ubuntu: Security Advisory for linux (USN-5003-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "Advisory-ID", value: "USN-5003-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-June/006089.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the USN-5003-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Norbert Slusarek discovered a race condition in the CAN BCM networking
protocol of the Linux kernel leading to multiple use-after-free
vulnerabilities. A local attacker could use this issue to execute arbitrary
code. (CVE-2021-3609)

It was discovered that the eBPF implementation in the Linux kernel did not
properly track bounds information for 32 bit registers when performing div
and mod operations. A local attacker could use this to possibly execute
arbitrary code. (CVE-2021-3600)

Or Cohen discovered that the SCTP implementation in the Linux kernel
contained a race condition in some situations, leading to a use-after-free
condition. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2021-23133)" );
	script_tag( name: "affected", value: "'linux' package(s) on Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1022-dell300x", ver: "4.15.0-1022.26", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1075-oracle", ver: "4.15.0-1075.83", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1089-raspi2", ver: "4.15.0-1089.94", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1103-gcp", ver: "4.15.0-1103.116", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1106-aws", ver: "4.15.0-1106.113", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1106-snapdragon", ver: "4.15.0-1106.115", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1118-azure", ver: "4.15.0-1118.131", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-147-generic", ver: "4.15.0-147.151", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-147-generic-lpae", ver: "4.15.0-147.151", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-147-lowlatency", ver: "4.15.0-147.151", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-aws-lts-18.04", ver: "4.15.0.1106.109", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-azure-lts-18.04", ver: "4.15.0.1118.91", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-dell300x", ver: "4.15.0.1022.24", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gcp-lts-18.04", ver: "4.15.0.1103.121", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic", ver: "4.15.0.147.134", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "4.15.0.147.134", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "4.15.0.147.134", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oracle-lts-18.04", ver: "4.15.0.1075.85", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-raspi2", ver: "4.15.0.1089.86", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-snapdragon", ver: "4.15.0.1106.109", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual", ver: "4.15.0.147.134", rls: "UBUNTU18.04 LTS" ) )){
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

