if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843194" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2017-06-06 06:27:24 +0200 (Tue, 06 Jun 2017)" );
	script_cve_id( "CVE-2014-3248", "CVE-2017-2295" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for puppet USN-3308-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'puppet'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Dennis Rowe discovered that Puppet
  incorrectly handled the search path. A local attacker could use this issue to
  possibly execute arbitrary code. (CVE-2014-3248) It was discovered that Puppet
  incorrectly handled YAML deserialization. A remote attacker could possibly use
  this issue to execute arbitrary code on the master. This update is incompatible
  with agents older than 3.2.2. (CVE-2017-2295)" );
	script_tag( name: "affected", value: "puppet on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3308-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3308-1/" );
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
	if(( res = isdpkgvuln( pkg: "puppet-common", ver: "3.4.3-1ubuntu1.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

