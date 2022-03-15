if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842391" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-30 05:14:24 +0200 (Thu, 30 Jul 2015)" );
	script_cve_id( "CVE-2015-5477", "CVE-2012-5689" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for bind9 USN-2693-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind9'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Jonathan Foote discovered that Bind
incorrectly handled certain TKEY queries. A remote attacker could use this issue
with a specially crafted packet to cause Bind to crash, resulting in a denial of
service. (CVE-2015-5477)

Pories Ediansyah discovered that Bind incorrectly handled certain
configurations involving DNS64. A remote attacker could use this issue with
a specially crafted query to cause Bind to crash, resulting in a denial of
service. This issue only affected Ubuntu 12.04 LTS. (CVE-2012-5689)" );
	script_tag( name: "affected", value: "bind9 on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2693-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2693-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.9.5.dfsg-3ubuntu0.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.8.1.dfsg.P1-4ubuntu0.12", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

