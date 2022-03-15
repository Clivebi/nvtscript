if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841932" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-08-15 05:56:43 +0200 (Fri, 15 Aug 2014)" );
	script_cve_id( "CVE-2014-3504" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_name( "Ubuntu Update for serf USN-2315-1" );
	script_tag( name: "affected", value: "serf on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Ben Reser discovered that serf did not correctly handle SSL
certificates with NUL bytes in the CommonName or SubjectAltNames fields. A
remote attacker could exploit this to perform a man in the middle attack to
view sensitive information or alter encrypted communications." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2315-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2315-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'serf'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libserf-1-1:i386", ver: "1.3.3-1ubuntu0.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libserf1", ver: "1.0.0-2ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

