if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842901" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-09-29 05:43:46 +0200 (Thu, 29 Sep 2016)" );
	script_cve_id( "CVE-2016-2119" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for samba USN-3092-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Stefan Metzmacher discovered that Samba
  incorrectly handled certain flags in SMB2/3 client connections. A remote attacker
  could use this issue to disable client signing and impersonate servers by
  performing a man in the middle attack.

Samba has been updated to 4.3.11 in Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
In addition to the security fix, the updated packages contain bug fixes,
new features, and possibly incompatible changes." );
	script_tag( name: "affected", value: "samba on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3092-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3092-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.3.11+dfsg-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.3.11+dfsg-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

