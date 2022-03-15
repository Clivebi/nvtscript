if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843547" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-12 05:54:16 +0200 (Tue, 12 Jun 2018)" );
	script_cve_id( "CVE-2018-1092", "CVE-2018-1093", "CVE-2018-10940", "CVE-2018-8087" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-31 10:30:00 +0000 (Wed, 31 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-aws USN-3676-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-aws'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "insight", value: "USN-3676-1 fixed vulnerabilities in the Linux
kernel for Ubuntu 16.04 LTS. This update provides the corresponding updates for the
Linux Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly handle corrupted meta data in some situations. An
attacker could use this to specially craft an ext4 file system that caused
a denial of service (system crash) when mounted. (CVE-2018-1092,
CVE-2018-1093)

It was discovered that the cdrom driver in the Linux kernel contained an
incorrect bounds check. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2018-10940)

It was discovered that the 802.11 software simulator implementation in the
Linux kernel contained a memory leak when handling certain error
conditions. A local attacker could possibly use this to cause a denial of
service (memory exhaustion). (CVE-2018-8087)" );
	script_tag( name: "affected", value: "linux-aws on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3676-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3676-2/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1023-aws", ver: "4.4.0-1023.23", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-128-generic", ver: "4.4.0-128.154~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-128-generic-lpae", ver: "4.4.0-128.154~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-128-lowlatency", ver: "4.4.0-128.154~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-128-powerpc-e500mc", ver: "4.4.0-128.154~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-128-powerpc-smp", ver: "4.4.0-128.154~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-128-powerpc64-emb", ver: "4.4.0-128.154~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-128-powerpc64-smp", ver: "4.4.0-128.154~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-aws", ver: "4.4.0.1023.23", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-lts-xenial", ver: "4.4.0.128.108", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lts-xenial", ver: "4.4.0.128.108", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-lts-xenial", ver: "4.4.0.128.108", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc-lts-xenial", ver: "4.4.0.128.108", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-smp-lts-xenial", ver: "4.4.0.128.108", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb-lts-xenial", ver: "4.4.0.128.108", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp-lts-xenial", ver: "4.4.0.128.108", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

