if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843396" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-08 07:04:42 +0100 (Fri, 08 Dec 2017)" );
	script_cve_id( "CVE-2017-16939", "CVE-2017-1000405", "CVE-2017-12146" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-hwe USN-3508-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-hwe'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3508-1 fixed vulnerabilities in the
  Linux kernel for Ubuntu 17.04. This update provides the corresponding updates
  for the Linux Hardware Enablement (HWE) kernel from Ubuntu 17.04 for Ubuntu
  16.04 LTS. Mohamed Ghannam discovered that a use-after-free vulnerability
  existed in the Netlink subsystem (XFRM) in the Linux kernel. A local attacker
  could use this to cause a denial of service (system crash) or possibly execute
  arbitrary code. (CVE-2017-16939) It was discovered that the Linux kernel did not
  properly handle copy-on- write of transparent huge pages. A local attacker could
  use this to cause a denial of service (application crashes) or possibly gain
  administrative privileges. (CVE-2017-1000405) Yonggang Guo discovered that a
  race condition existed in the driver subsystem in the Linux kernel. A local
  attacker could use this to possibly gain administrative privileges.
  (CVE-2017-12146)" );
	script_tag( name: "affected", value: "linux-hwe on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3508-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3508-2/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-42-generic", ver: "4.10.0-42.46~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-42-generic-lpae", ver: "4.10.0-42.46~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-42-lowlatency", ver: "4.10.0-42.46~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-hwe-16.04", ver: "4.10.0.42.44", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-hwe-16.04", ver: "4.10.0.42.44", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-hwe-16.04", ver: "4.10.0.42.44", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

