if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842378" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-23 06:27:57 +0200 (Thu, 23 Jul 2015)" );
	script_cve_id( "CVE-2015-1331", "CVE-2015-1334" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:C/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for lxc USN-2675-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lxc'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Roman Fiedler discovered that LXC had a
directory traversal flaw when creating lock files. A local attacker could exploit
this flaw to create an arbitrary file as the root user. (CVE-2015-1331)

Roman Fiedler discovered that LXC incorrectly trusted the container's proc
filesystem to set up AppArmor profile changes and SELinux domain transitions. A
local attacker could exploit this flaw to run programs inside the container
that are not confined by AppArmor or SELinux. (CVE-2015-1334)" );
	script_tag( name: "affected", value: "lxc on Ubuntu 14.10,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2675-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2675-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "liblxc1", ver: "1.1.0~alpha2-0ubuntu3.3", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "lxc", ver: "1.1.0~alpha2-0ubuntu3.3", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "liblxc1", ver: "1.0.7-0ubuntu0.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "lxc", ver: "1.0.7-0ubuntu0.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

