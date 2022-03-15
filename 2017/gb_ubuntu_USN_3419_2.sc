if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843307" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-19 07:42:01 +0200 (Tue, 19 Sep 2017)" );
	script_cve_id( "CVE-2017-1000251", "CVE-2017-7541" );
	script_tag( name: "cvss_base", value: "7.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-03 19:00:00 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-hwe USN-3419-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-hwe'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3419-1 fixed vulnerabilities in the
  Linux kernel for Ubuntu 17.04. This update provides the corresponding updates
  for the Linux Hardware Enablement (HWE) kernel from Ubuntu 17.04 for Ubuntu
  16.04 LTS. It was discovered that a buffer overflow existed in the Bluetooth
  stack of the Linux kernel when handling L2CAP configuration responses. A
  physically proximate attacker could use this to cause a denial of service
  (system crash). (CVE-2017-1000251) It was discovered that a buffer overflow
  existed in the Broadcom FullMAC WLAN driver in the Linux kernel. A local
  attacker could use this to cause a denial of service (system crash) or possibly
  execute arbitrary code. (CVE-2017-7541)" );
	script_tag( name: "affected", value: "linux-hwe on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3419-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3419-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-35-generic", ver: "4.10.0-35.39~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-35-generic-lpae", ver: "4.10.0-35.39~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-35-lowlatency", ver: "4.10.0-35.39~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-hwe-16.04", ver: "4.10.0.35.37", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-hwe-16.04", ver: "4.10.0.35.37", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-hwe-16.04", ver: "4.10.0.35.37", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

