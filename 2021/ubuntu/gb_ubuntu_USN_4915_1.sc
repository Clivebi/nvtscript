if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844902" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2021-3493", "CVE-2021-3492" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-31 17:15:00 +0000 (Mon, 31 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 03:00:23 +0000 (Fri, 16 Apr 2021)" );
	script_name( "Ubuntu: Security Advisory for linux-oem-5.6 (USN-4915-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU20\\.04 LTS" );
	script_xref( name: "Advisory-ID", value: "USN-4915-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-April/005975.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-oem-5.6'
  package(s) announced via the USN-4915-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the overlayfs implementation in the Linux kernel did
not properly validate the application of file system capabilities with
respect to user namespaces. A local attacker could use this to gain
elevated privileges. (CVE-2021-3493)

Vincent Dehors discovered that the shiftfs file system in the Ubuntu Linux
kernel did not properly handle faults in copy_from_user() when passing
through ioctls to an underlying file system. A local attacker could use
this to cause a denial of service (memory exhaustion) or execute arbitrary
code. (CVE-2021-3492)" );
	script_tag( name: "affected", value: "'linux-oem-5.6' package(s) on Ubuntu 20.04 LTS." );
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.6.0-1054-oem", ver: "5.6.0-1054.58", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oem-20.04", ver: "5.6.0.1054.50", rls: "UBUNTU20.04 LTS" ) )){
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

