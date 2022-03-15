if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841419" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-05-09 10:26:27 +0530 (Thu, 09 May 2013)" );
	script_cve_id( "CVE-2013-2038" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for gpsd USN-1820-1" );
	script_xref( name: "USN", value: "1820-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1820-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gpsd'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	script_tag( name: "affected", value: "gpsd on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that gpsd incorrectly handled certain malformed GPS data.
  An attacker could use this issue to cause gpsd to crash, resulting in a
  denial of service, or possibly execute arbitrary code." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
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
	if(( res = isdpkgvuln( pkg: "gpsd", ver: "3.4-2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

