if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842868" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-25 05:40:23 +0200 (Thu, 25 Aug 2016)" );
	script_cve_id( "CVE-2015-2059", "CVE-2015-8948", "CVE-2016-6262", "CVE-2016-6261", "CVE-2016-6263" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libidn USN-3068-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libidn'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Thijs Alkemade, Gustavo Grieco, Daniel
  Stenberg, and Nikos Mavrogiannopoulos discovered that Libidn incorrectly handled
  invalid UTF-8 characters. A remote attacker could use this issue to cause Libidn
  to crash, resulting in a denial of service, or possibly disclose sensitive
  memory. This issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
  (CVE-2015-2059)

Hanno B&#246 ck discovered that Libidn incorrectly handled certain input. A
remote attacker could possibly use this issue to cause Libidn to crash,
resulting in a denial of service. (CVE-2015-8948, CVE-2016-6262,
CVE-2016-6261, CVE-2016-6263)" );
	script_tag( name: "affected", value: "libidn on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3068-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3068-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libidn11:i386", ver: "1.28-1ubuntu2.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libidn11:amd64", ver: "1.28-1ubuntu2.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libidn11:i386", ver: "1.23-2ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libidn11:amd64", ver: "1.23-2ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libidn11:i386", ver: "1.32-3ubuntu1.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libidn11:amd64", ver: "1.32-3ubuntu1.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

