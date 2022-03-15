if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843337" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-12 10:27:28 +0200 (Thu, 12 Oct 2017)" );
	script_cve_id( "CVE-2016-5009", "CVE-2016-7031", "CVE-2016-8626", "CVE-2016-9579" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for ceph USN-3452-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ceph'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Ceph incorrectly
  handled the handle_command function. A remote authenticated user could use this
  issue to cause Ceph to crash, resulting in a denial of service. (CVE-2016-5009)
  Rahul Aggarwal discovered that Ceph incorrectly handled the authenticated-read
  ACL. A remote attacker could possibly use this issue to list bucket contents via
  a URL. (CVE-2016-7031) Diluga Salome discovered that Ceph incorrectly handled
  certain POST objects with null conditions. A remote attacker could possibly use
  this issue to cause Ceph to crash, resulting in a denial of service.
  (CVE-2016-8626) Yang Liu discovered that Ceph incorrectly handled invalid HTTP
  Origin headers. A remote attacker could possibly use this issue to cause Ceph to
  crash, resulting in a denial of service. (CVE-2016-9579)" );
	script_tag( name: "affected", value: "ceph on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3452-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3452-1/" );
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
	if(( res = isdpkgvuln( pkg: "ceph", ver: "0.80.11-0ubuntu1.14.04.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ceph-common", ver: "0.80.11-0ubuntu1.14.04.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

