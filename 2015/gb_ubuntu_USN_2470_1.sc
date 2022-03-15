if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842045" );
	script_version( "2020-02-28T09:03:19+0000" );
	script_tag( name: "last_modification", value: "2020-02-28 09:03:19 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-01-23 12:58:04 +0100 (Fri, 23 Jan 2015)" );
	script_cve_id( "CVE-2014-9390" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for git USN-2470-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'git'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Matt Mackall and Augie Fackler discovered that
Git incorrectly handled certain filesystem paths. A remote attacker could possibly
use this issue to execute arbitrary code if the Git tree is stored in an HFS+ or NTFS
filesystem. The remote attacker would need write access to a Git repository that the
victim pulls from." );
	script_tag( name: "affected", value: "git on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2470-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2470-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS|12\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "git", ver: "1:2.1.0-1ubuntu0.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "git", ver: "1:1.9.1-1ubuntu0.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "git", ver: "1:1.7.9.5-1ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

