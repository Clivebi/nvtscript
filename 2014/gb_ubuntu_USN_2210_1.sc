if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841810" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-12 09:13:13 +0530 (Mon, 12 May 2014)" );
	script_cve_id( "CVE-2014-2707" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for cups-filters USN-2210-1" );
	script_tag( name: "affected", value: "cups-filters on Ubuntu 14.04 LTS" );
	script_tag( name: "insight", value: "Sebastian Krahmer discovered that cups-browsed incorrectly
filtered remote printer names and strings. A remote attacker could use this
issue to possibly execute arbitrary commands. (CVE-2014-2707)

Johannes Meixner discovered that cups-browsed ignored invalid BrowseAllow
directives. This could cause it to accept browse packets from all hosts,
contrary to intended configuration." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2210-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2210-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cups-filters'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "cups-browsed", ver: "1.0.52-0ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

