if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843126" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-05 06:36:41 +0200 (Wed, 05 Apr 2017)" );
	script_cve_id( "CVE-2017-7358" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for lightdm USN-3255-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lightdm'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that LightDM incorrectly
  handled home directory creation for guest users. A local attacker could use this
  issue to gain ownership of arbitrary directory paths and possibly gain
  administrative privileges." );
	script_tag( name: "affected", value: "lightdm on Ubuntu 16.10,
  Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3255-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3255-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(16\\.10|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "lightdm", ver: "1.19.5-0ubuntu1.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "lightdm", ver: "1.18.3-0ubuntu1.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

