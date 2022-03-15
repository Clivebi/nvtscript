if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842869" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-25 05:40:32 +0200 (Thu, 25 Aug 2016)" );
	script_cve_id( "CVE-2015-8947", "CVE-2016-2052" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for harfbuzz USN-3067-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'harfbuzz'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Kostya Serebryany discovered that HarfBuzz
  incorrectly handled memory. A remote attacker could use this issue to cause
  HarfBuzz to crash, resulting in a denial of service, or possibly execute arbitrary
  code. (CVE-2015-8947)

It was discovered that HarfBuzz incorrectly handled certain length checks.
A remote attacker could use this issue to cause HarfBuzz to crash,
resulting in a denial of service, or possibly execute arbitrary code.
This issue only applied to Ubuntu 16.04 LTS. (CVE-2016-2052)" );
	script_tag( name: "affected", value: "harfbuzz on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3067-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3067-1/" );
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
	if(( res = isdpkgvuln( pkg: "libharfbuzz0b:i386", ver: "0.9.27-1ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libharfbuzz0b:amd64", ver: "0.9.27-1ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libharfbuzz0b:i386", ver: "1.0.1-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libharfbuzz0b:amd64", ver: "1.0.1-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

