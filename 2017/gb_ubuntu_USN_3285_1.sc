if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843160" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-12 06:50:42 +0200 (Fri, 12 May 2017)" );
	script_cve_id( "CVE-2017-8900" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for lightdm USN-3285-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lightdm'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Tyler Hicks discovered that LightDM did not
  confine the user session for guest users. An attacker with physical access could
  use this issue to access files and other resources that they should not be able
  to access. In the default installation, this includes files in the home
  directories of other users on the system. This update fixes the issue by
  disabling the guest session. It may be re-enabled in a future update. Please see
  the bug referenced below for instructions on how to manually re-enable the guest
  session." );
	script_tag( name: "affected", value: "lightdm on Ubuntu 17.04,
  Ubuntu 16.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3285-1" );
	script_xref( name: "URL", value: "https://www.ubuntu.com/usn/usn-3285-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(17\\.04|16\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "lightdm", ver: "1.22.0-0ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "lightdm", ver: "1.19.5-0ubuntu1.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

