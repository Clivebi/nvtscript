if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1374-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840908" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-09 19:03:29 +0530 (Fri, 09 Mar 2012)" );
	script_cve_id( "CVE-2012-0870" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1374-1" );
	script_name( "Ubuntu Update for samba USN-1374-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU8\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1374-1" );
	script_tag( name: "affected", value: "samba on Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Andy Davis discovered that Samba incorrectly handled certain AndX offsets.
  A remote attacker could send a specially crafted request to the server and
  cause a denial of service, or possibly execute arbitrary code." );
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
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "samba", ver: "3.0.28a-1ubuntu4.17", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

