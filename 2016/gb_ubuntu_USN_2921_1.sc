if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842677" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-08 12:37:34 +0530 (Tue, 08 Mar 2016)" );
	script_cve_id( "CVE-2014-6270", "CVE-2016-2571" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for squid3 USN-2921-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid3'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Sebastian Krahmer discovered that Squid
  incorrectly handled certain SNMP requests. If SNMP is enabled, a remote attacker
  could use this issue to cause Squid to crash, resulting in a denial of service,
  or possibly execute arbitrary code. (CVE-2014-6270)

  Alex Rousskov discovered that Squid incorrectly handled certain malformed
  responses. A remote attacker could possibly use this issue to cause Squid
  to crash, resulting in a denial of service. (CVE-2016-2571)" );
	script_tag( name: "affected", value: "squid3 on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2921-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2921-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "squid3", ver: "3.3.8-1ubuntu6.6", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "squid3", ver: "3.1.19-1ubuntu3.12.04.6", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "squid3", ver: "3.3.8-1ubuntu16.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

