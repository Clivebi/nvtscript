if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842231" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-09 11:09:41 +0200 (Tue, 09 Jun 2015)" );
	script_cve_id( "CVE-2012-1164", "CVE-2013-4449", "CVE-2015-1545" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openldap USN-2622-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openldap'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenLDAP incorrectly
handled certain search queries that returned empty attributes. A remote attacker
could use this issue to cause OpenLDAP to assert, resulting in a denial of service.
This issue only affected Ubuntu 12.04 LTS. (CVE-2012-1164)

Michael Vishchers discovered that OpenLDAP improperly counted references
when the rwm overlay was used. A remote attacker could use this issue to
cause OpenLDAP to crash, resulting in a denial of service. (CVE-2013-4449)

It was discovered that OpenLDAP incorrectly handled certain empty attribute
lists in search requests. A remote attacker could use this issue to cause
OpenLDAP to crash, resulting in a denial of service. (CVE-2015-1545)" );
	script_tag( name: "affected", value: "openldap on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2622-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2622-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS|12\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "slapd", ver: "2.4.31-1+nmu2ubuntu11.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "slapd", ver: "2.4.31-1+nmu2ubuntu8.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "slapd", ver: "2.4.28-1.1ubuntu4.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

