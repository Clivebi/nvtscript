if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842894" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-09-22 05:37:46 +0200 (Thu, 22 Sep 2016)" );
	script_cve_id( "CVE-2016-7044", "CVE-2016-7045" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for irssi USN-3086-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'irssi'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Gabriel Campana and Adrien Guinet discovered
  that the format parsing code in Irssi did not properly verify 24bit color codes.
  A remote attacker could use this to cause a denial of service (application crash).
  (CVE-2016-7044)

Gabriel Campana and Adrien Guinet discovered that a buffer overflow existed
in the format parsing code in Irssi. A remote attacker could use this to
cause a denial of service (application crash). (CVE-2016-7045)" );
	script_tag( name: "affected", value: "irssi on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3086-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3086-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "irssi", ver: "0.8.19-1ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

