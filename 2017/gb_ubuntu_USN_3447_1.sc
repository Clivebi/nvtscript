if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843335" );
	script_version( "2021-09-16T09:01:51+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 09:01:51 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-12 10:27:04 +0200 (Thu, 12 Oct 2017)" );
	script_cve_id( "CVE-2016-4428" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-09 15:08:00 +0000 (Tue, 09 Mar 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for horizon USN-3447-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'horizon'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Beth Lancaster and Brandon Sawyers
  discovered that OpenStack Horizon was incorrect protected against cross-site
  scripting (XSS) attacks. A remote authenticated user could use this issue to
  inject web script or HTML in a dashboard form." );
	script_tag( name: "affected", value: "horizon on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3447-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3447-1/" );
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
	if(( res = isdpkgvuln( pkg: "openstack-dashboard", ver: "1:2014.1.5-0ubuntu2.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

