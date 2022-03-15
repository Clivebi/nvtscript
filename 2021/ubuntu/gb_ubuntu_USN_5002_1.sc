if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844989" );
	script_version( "2021-07-06T12:11:22+0000" );
	script_cve_id( "CVE-2021-3609" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-06 12:11:22 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-24 03:01:08 +0000 (Thu, 24 Jun 2021)" );
	script_name( "Ubuntu: Security Advisory for linux-gke-5.3 (USN-5002-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "Advisory-ID", value: "USN-5002-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-June/006088.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-gke-5.3'
  package(s) announced via the USN-5002-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Norbert Slusarek discovered a race condition in the CAN BCM networking
protocol of the Linux kernel leading to multiple use-after-free
vulnerabilities. A local attacker could use this issue to execute arbitrary
code." );
	script_tag( name: "affected", value: "'linux-gke-5.3' package(s) on Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-1041-raspi2", ver: "5.3.0-1041.43", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-1044-gke", ver: "5.3.0-1044.47", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-75-generic", ver: "5.3.0-75.71", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-75-lowlatency", ver: "5.3.0-75.71", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke-5.3", ver: "5.3.0.1044.27", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gkeop-5.3", ver: "5.3.0.75.132", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-raspi2-hwe-18.04", ver: "5.3.0.1041.30", rls: "UBUNTU18.04 LTS" ) )){
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

