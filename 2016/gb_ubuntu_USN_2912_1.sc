if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842661" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-02-24 06:25:31 +0100 (Wed, 24 Feb 2016)" );
	script_cve_id( "CVE-2015-3146", "CVE-2016-0739" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libssh USN-2912-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libssh'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mariusz Ziulek discovered that libssh
  incorrectly handled certain packets. A remote attacker could possibly
  use this issue to cause libssh to crash, resulting in a denial of service.
  (CVE-2015-3146)

  Aris Adamantiadis discovered that libssh incorrectly generated ephemeral
  secret keys of 128 bits instead of the recommended 1024 or 2048 bits when
  using the diffie-hellman-group1 and diffie-hellman-group14 methods. If a
  remote attacker were able to perform a man-in-the-middle attack, this flaw
  could be exploited to view sensitive information. (CVE-2016-0739)" );
	script_tag( name: "affected", value: "libssh on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2912-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2912-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libssh-4", ver: "0.6.1-0ubuntu3.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssh-4", ver: "0.5.2-1ubuntu0.12.04.6", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libssh-4", ver: "0.6.3-3ubuntu3.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

