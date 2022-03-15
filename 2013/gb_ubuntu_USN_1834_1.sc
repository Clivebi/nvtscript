if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841438" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-05-27 11:55:47 +0530 (Mon, 27 May 2013)" );
	script_cve_id( "CVE-2013-1929", "CVE-2013-3301" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux-lts-quantal USN-1834-1" );
	script_xref( name: "USN", value: "1834-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1834-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-quantal'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	script_tag( name: "affected", value: "linux-lts-quantal on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A buffer overflow vulnerability was discovered in the Broadcom tg3 ethernet
  driver for the Linux kernel. A local user could exploit this flaw to cause
  a denial of service (crash the system) or potentially escalate privileges
  on the system. (CVE-2013-1929)

  A flaw was discovered in the Linux kernel's ftrace subsystem interface. A
  local user could exploit this flaw to cause a denial of service (system
  crash). (CVE-2013-3301)" );
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
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.5.0-31-generic", ver: "3.5.0-31.52~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

