if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843336" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2017-10-12 10:27:08 +0200 (Thu, 12 Oct 2017)" );
	script_cve_id( "CVE-2015-5223", "CVE-2016-0737", "CVE-2016-0738" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for swift USN-3451-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'swift'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenStack Swift
  incorrectly handled tempurls. A remote authenticated user in possession of a
  tempurl key authorized for PUT could retrieve other objects in the same Swift
  account. (CVE-2015-5223) Romain Le Disez and rjan Persson discovered that
  OpenStack Swift incorrectly closed client connections. A remote attacker could
  possibly use this issue to consume resources, resulting in a denial of service.
  (CVE-2016-0737, CVE-2016-0738)" );
	script_tag( name: "affected", value: "swift on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3451-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3451-1/" );
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
	if(( res = isdpkgvuln( pkg: "python-swift", ver: "1.13.1-0ubuntu1.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "swift", ver: "1.13.1-0ubuntu1.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

