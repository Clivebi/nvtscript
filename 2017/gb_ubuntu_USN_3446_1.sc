if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843333" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2017-10-12 10:26:31 +0200 (Thu, 12 Oct 2017)" );
	script_cve_id( "CVE-2015-5251", "CVE-2015-5286", "CVE-2016-0757" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for glance USN-3446-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glance'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Hemanth Makkapati discovered that OpenStack
  Glance incorrectly handled access restrictions. A remote authenticated user
  could use this issue to change the status of images, contrary to access
  restrictions. (CVE-2015-5251) Mike Fedosin and Alexei Galkin discovered that
  OpenStack Glance incorrectly handled the storage quota. A remote authenticated
  user could use this issue to consume disk resources, leading to a denial of
  service. (CVE-2015-5286) Erno Kuvaja discovered that OpenStack Glance
  incorrectly handled the show_multiple_locations option. When
  show_multiple_locations is enabled, a remote authenticated user could change an
  image status and upload new image data. (CVE-2016-0757)" );
	script_tag( name: "affected", value: "glance on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3446-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3446-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "glance-common", ver: "1:2014.1.5-0ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

