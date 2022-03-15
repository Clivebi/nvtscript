if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843911" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2019-3825" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:49:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-02-21 04:04:45 +0100 (Thu, 21 Feb 2019)" );
	script_name( "Ubuntu Update for gdm3 USN-3892-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(18\\.04 LTS|18\\.10)" );
	script_xref( name: "USN", value: "3892-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3892-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gdm3'
  package(s) announced via the USN-3892-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Burghard Britzke discovered that GDM incorrectly handled certain
configurations. An attacker could possibly use this issue to get
unauthorized access to a different user." );
	script_tag( name: "affected", value: "gdm3 on Ubuntu 18.10,
  Ubuntu 18.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "gdm3", ver: "3.28.3-0ubuntu18.04.4", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "gdm3", ver: "3.30.1-1ubuntu5.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

