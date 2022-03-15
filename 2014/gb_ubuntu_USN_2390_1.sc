if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842015" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-10-29 05:53:47 +0100 (Wed, 29 Oct 2014)" );
	script_cve_id( "CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3698" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "Ubuntu Update for pidgin USN-2390-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pidgin'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Jacob Appelbaum and an anonymous person
discovered that Pidgin incorrectly handled certificate validation. A remote attacker
could exploit this to perform a man in the middle attack to view sensitive
information or alter encrypted communications. (CVE-2014-3694)

Yves Younan and Richard Johnson discovered that Pidgin incorrectly handled
certain malformed MXit emoticons. A malicious remote server or a man in the
middle could use this issue to cause Pidgin to crash, resulting in a denial
of service. (CVE-2014-3695)

Yves Younan and Richard Johnson discovered that Pidgin incorrectly handled
certain malformed Groupwise messages. A malicious remote server or a man in
the middle could use this issue to cause Pidgin to crash, resulting in a
denial of service. (CVE-2014-3696)

Thijs Alkemade and Paul Aurich discovered that Pidgin incorrectly handled
memory when processing XMPP messages. A malicious remote server or user
could use this issue to cause Pidgin to disclosure arbitrary memory,
resulting in an information leak. (CVE-2014-3698)" );
	script_tag( name: "affected", value: "pidgin on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2390-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2390-1/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libpurple0", ver: "1:2.10.9-0ubuntu3.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pidgin", ver: "1:2.10.9-0ubuntu3.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpurple0", ver: "1:2.10.3-0ubuntu1.6", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pidgin", ver: "1:2.10.3-0ubuntu1.6", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

