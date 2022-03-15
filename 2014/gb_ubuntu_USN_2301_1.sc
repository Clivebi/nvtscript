if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841910" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-28 16:38:45 +0530 (Mon, 28 Jul 2014)" );
	script_cve_id( "CVE-2014-0012", "CVE-2014-1402" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for jinja2 USN-2301-1" );
	script_tag( name: "affected", value: "jinja2 on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that Jinja2 incorrectly handled temporary
cache files and directories. A local attacker could use this issue to possibly
gain privileges." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2301-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2301-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jinja2'
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
	if(( res = isdpkgvuln( pkg: "python-jinja2", ver: "2.6-1ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-jinja2", ver: "2.6-1ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

