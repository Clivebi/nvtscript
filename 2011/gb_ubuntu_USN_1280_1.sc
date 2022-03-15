if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1280-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840812" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-11-25 12:00:38 +0530 (Fri, 25 Nov 2011)" );
	script_xref( name: "USN", value: "1280-1" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2011-1585", "CVE-2011-2496" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-1280-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1280-1" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that CIFS incorrectly handled authentication. When a user
  had a CIFS share mounted that required authentication, a local user could
  mount the same share without knowing the correct password. (CVE-2011-1585)

  Robert Swiecki discovered that mapping extensions were incorrectly handled.
  A local attacker could exploit this to crash the system, leading to a
  denial of service. (CVE-2011-2496)" );
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
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-903-omap4", ver: "2.6.35-903.27", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

