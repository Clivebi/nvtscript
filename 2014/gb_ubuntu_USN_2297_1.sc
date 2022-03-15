if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841908" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-28 16:38:09 +0530 (Mon, 28 Jul 2014)" );
	script_cve_id( "CVE-2014-1419" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for acpi-support USN-2297-1" );
	script_tag( name: "affected", value: "acpi-support on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "CESG discovered that acpi-support incorrectly handled certain
privileged operations when checking for power management daemons. A local
attacker could use this flaw to execute arbitrary code and elevate privileges
to root." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2297-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2297-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'acpi-support'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "acpi-support", ver: "0.140.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

