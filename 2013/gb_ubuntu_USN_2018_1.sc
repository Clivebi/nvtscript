if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841630" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-11-18 17:03:39 +0530 (Mon, 18 Nov 2013)" );
	script_cve_id( "CVE-2012-5374", "CVE-2012-5375", "CVE-2013-2147" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:N/A:C" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-2018-1" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "A denial of service flaw was discovered in the Btrfs file
system in the Linux kernel. A local user could cause a denial of service by
creating a large number of files with names that have the same CRC32 hash
value. (CVE-2012-5374)

A denial of service flaw was discovered in the Btrfs file system in the
Linux kernel. A local user could cause a denial of service (prevent file
creation) for a victim, by creating a file with a specific CRC32C hash
value in a directory important to the victim. (CVE-2012-5375)

Dan Carpenter discovered an information leak in the HP Smart Array and
Compaq SMART2 disk-array driver in the Linux kernel. A local user could
exploit this flaw to obtain sensitive information from kernel memory.
(CVE-2013-2147)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2018-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2018-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-ti-omap4'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-1440-omap4", ver: "3.2.0-1440.59", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

