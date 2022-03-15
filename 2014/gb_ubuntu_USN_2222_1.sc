if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841833" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-02 15:02:08 +0530 (Mon, 02 Jun 2014)" );
	script_cve_id( "CVE-2014-0240", "CVE-2014-0242" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for mod-wsgi USN-2222-1" );
	script_tag( name: "affected", value: "mod-wsgi on Ubuntu 14.04 LTS,
  Ubuntu 13.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "R&#243 bert Kisteleki discovered mod_wsgi incorrectly checked
setuid return values. A malicious application could use this issue to cause a
local privilege escalation when using daemon mode. (CVE-2014-0240)

Buck Golemon discovered that mod_wsgi used memory that had been freed.
A remote attacker could use this issue to read process memory via the
Content-Type response header. This issue only affected Ubuntu 12.04 LTS.
(CVE-2014-0242)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2222-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2222-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mod-wsgi'
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
	if(( res = isdpkgvuln( pkg: "libapache2-mod-wsgi", ver: "3.4-4ubuntu2.1.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libapache2-mod-wsgi-py3", ver: "3.4-4ubuntu2.1.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-wsgi", ver: "3.3-4ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libapache2-mod-wsgi-py3", ver: "3.3-4ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-wsgi", ver: "3.4-4ubuntu2.1.13.10.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libapache2-mod-wsgi-py3", ver: "3.4-4ubuntu2.1.13.10.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

