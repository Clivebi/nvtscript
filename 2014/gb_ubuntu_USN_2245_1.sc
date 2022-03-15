if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841858" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-17 10:06:07 +0530 (Tue, 17 Jun 2014)" );
	script_cve_id( "CVE-2013-6370", "CVE-2013-6371" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for json-c USN-2245-1" );
	script_tag( name: "affected", value: "json-c on Ubuntu 14.04 LTS,
  Ubuntu 13.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Florian Weimer discovered that json-c incorrectly handled
buffer lengths. An attacker could use this issue with a specially-crafted large
JSON document to cause json-c to crash, resulting in a denial of service.
(CVE-2013-6370)

Florian Weimer discovered that json-c incorrectly handled hash arrays. An
attacker could use this issue with a specially-crafted JSON document to
cause json-c to consume CPU resources, resulting in a denial of service.
(CVE-2013-6371)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2245-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2245-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'json-c'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|13\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libjson0:i386", ver: "0.11-3ubuntu1.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libjson0", ver: "0.9-1ubuntu1.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libjson0:i386", ver: "0.11-2ubuntu1.2", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

