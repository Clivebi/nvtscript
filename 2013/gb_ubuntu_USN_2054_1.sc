if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841654" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-17 12:08:41 +0530 (Tue, 17 Dec 2013)" );
	script_cve_id( "CVE-2012-6150", "CVE-2013-4408", "CVE-2013-4475" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for samba USN-2054-1" );
	script_tag( name: "affected", value: "samba on Ubuntu 13.10,
  Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that Winbind incorrectly handled invalid
group names with the require_membership_of parameter. If an administrator used
an invalid group name by mistake, access was granted instead of having the
login fail. (CVE-2012-6150)

Stefan Metzmacher and Michael Adam discovered that Samba incorrectly
handled DCE-RPC fragment length fields. A remote attacker could use this
issue to cause Samba to crash, resulting in a denial of service, or
possibly execute arbitrary code as the root user. (CVE-2013-4408)

Hemanth Thummala discovered that Samba incorrectly handled file
permissions when vfs_streams_depot or vfs_streams_xattr were enabled. A
remote attacker could use this issue to bypass intended restrictions.
(CVE-2013-4475)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2054-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2054-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.10|12\\.04 LTS|10\\.04 LTS|13\\.10|13\\.04)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libpam-winbind", ver: "2:3.6.6-3ubuntu5.3", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:3.6.6-3ubuntu5.3", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpam-winbind", ver: "2:3.6.3-2ubuntu2.9", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:3.6.3-2ubuntu2.9", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:3.4.7~dfsg-1ubuntu3.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "winbind", ver: "2:3.4.7~dfsg-1ubuntu3.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libpam-winbind", ver: "2:3.6.18-1ubuntu3.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:3.6.18-1ubuntu3.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "libpam-winbind", ver: "2:3.6.9-1ubuntu1.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:3.6.9-1ubuntu1.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

