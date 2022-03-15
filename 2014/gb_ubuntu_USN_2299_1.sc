if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841915" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-28 16:41:33 +0530 (Mon, 28 Jul 2014)" );
	script_cve_id( "CVE-2014-0117", "CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for apache2 USN-2299-1" );
	script_tag( name: "affected", value: "apache2 on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "Marek Kroemeke discovered that the mod_proxy module incorrectly
handled certain requests. A remote attacker could use this issue to cause the
server to stop responding, leading to a denial of service. This issue only
affected Ubuntu 14.04 LTS. (CVE-2014-0117)

Giancarlo Pellegrino and Davide Balzarotti discovered that the mod_deflate
module incorrectly handled body decompression. A remote attacker could use
this issue to cause resource consumption, leading to a denial of service.
(CVE-2014-0118)

Marek Kroemeke and others discovered that the mod_status module incorrectly
handled certain requests. A remote attacker could use this issue to cause
the server to stop responding, leading to a denial of service, or possibly
execute arbitrary code. (CVE-2014-0226)

Rainer Jung discovered that the mod_cgid module incorrectly handled certain
scripts. A remote attacker could use this issue to cause the server to stop
responding, leading to a denial of service. (CVE-2014-0231)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2299-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2299-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|10\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.7-1ubuntu4.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "apache2.2-bin", ver: "2.2.22-1ubuntu1.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "apache2.2-bin", ver: "2.2.14-5ubuntu8.14", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

