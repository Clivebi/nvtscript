if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843465" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-06 08:39:36 +0100 (Tue, 06 Mar 2018)" );
	script_cve_id( "CVE-2017-14461", "CVE-2017-15130" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-04 01:29:00 +0000 (Wed, 04 Apr 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for dovecot USN-3587-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dovecot'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Dovecot incorrectly
  handled parsing certain email addresses. A remote attacker could use this issue
  to cause Dovecot to crash, resulting in a denial of service, or possibly obtain
  sensitive information. (CVE-2017-14461) It was discovered that Dovecot
  incorrectly handled TLS SNI config lookups. A remote attacker could possibly use
  this issue to cause Dovecot to crash, resulting in a denial of service.
  (CVE-2017-15130)" );
	script_tag( name: "affected", value: "dovecot on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3587-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3587-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "dovecot-core", ver: "1:2.2.9-1ubuntu2.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "dovecot-core", ver: "1:2.2.27-3ubuntu1.3", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "dovecot-core", ver: "1:2.2.22-1ubuntu2.7", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

