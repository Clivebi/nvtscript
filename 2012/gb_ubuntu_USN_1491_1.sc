if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1491-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841061" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-03 10:25:42 +0530 (Tue, 03 Jul 2012)" );
	script_cve_id( "CVE-2012-2313", "CVE-2012-2319" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1491-1" );
	script_name( "Ubuntu Update for linux-ec2 USN-1491-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1491-1" );
	script_tag( name: "affected", value: "linux-ec2 on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Stephan Mueller reported a flaw in the Linux kernel's dl2k network driver's
  handling of ioctls. An unprivileged local user could leverage this flaw to
  cause a denial of service. (CVE-2012-2313)

  Timo Warns reported multiple flaws in the Linux kernel's hfsplus
  filesystem. An unprivileged local user could exploit these flaws to gain
  root system privileges. (CVE-2012-2319)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-345-ec2", ver: "2.6.32-345.50", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

