if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842679" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-10 06:16:57 +0100 (Thu, 10 Mar 2016)" );
	script_cve_id( "CVE-2015-7560", "CVE-2016-0771", "CVE-2013-0213", "CVE-2013-0214" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for samba USN-2922-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Jeremy Allison discovered that Samba
  incorrectly handled ACLs on symlink paths. A remote attacker could use this
  issue to overwrite the ownership of ACLs using symlinks. (CVE-2015-7560)

  Garming Sam and Douglas Bagnall discovered that the Samba internal DNS
  server incorrectly handled certain DNS TXT records. A remote attacker could
  use this issue to cause Samba to crash, resulting in a denial of service,
  or possibly obtain uninitialized memory contents. This issue only applied
  to Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2016-0771)

  It was discovered that the Samba Web Administration Tool (SWAT) was
  vulnerable to clickjacking and cross-site request forgery attacks. This
  issue only affected Ubuntu 12.04 LTS. (CVE-2013-0213, CVE-2013-0214)" );
	script_tag( name: "affected", value: "samba on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2922-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2922-1/" );
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
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.1.6+dfsg-1ubuntu2.14.04.13", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:3.6.3-2ubuntu2.17", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "swat", ver: "2:3.6.3-2ubuntu2.17", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.1.17+dfsg-4ubuntu3.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

