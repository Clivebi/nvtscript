if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843925" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2019-9020", "CVE-2019-9024", "CVE-2019-9021", "CVE-2019-9022", "CVE-2019-9023" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-18 18:15:00 +0000 (Tue, 18 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-03-07 04:11:41 +0100 (Thu, 07 Mar 2019)" );
	script_name( "Ubuntu Update for php7.0 USN-3902-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3902-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3902-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php7.0'
  package(s) announced via the USN-3902-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present
on the target host." );
	script_tag( name: "insight", value: "It was discovered that the PHP XML-RPC module
incorrectly handled decoding XML data. A remote attacker could possibly use this
issue to cause PHP to crash, resulting in a denial of service. (CVE-2019-9020, CVE-2019-9024)

It was discovered that the PHP PHAR module incorrectly handled certain
filenames. A remote attacker could possibly use this issue to cause PHP to
crash, resulting in a denial of service. (CVE-2019-9021)

It was discovered that PHP incorrectly parsed certain DNS responses. A
remote attacker could possibly use this issue to cause PHP to crash,
resulting in a denial of service. This issue only affected Ubuntu 16.04
LTS. (CVE-2019-9022)

It was discovered that PHP incorrectly handled mbstring regular
expressions. A remote attacker could possibly use this issue to cause PHP
to crash, resulting in a denial of service. (CVE-2019-9023)" );
	script_tag( name: "affected", value: "php7.0 on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.5.9+dfsg-1ubuntu4.27", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.5.9+dfsg-1ubuntu4.27", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.5.9+dfsg-1ubuntu4.27", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.5.9+dfsg-1ubuntu4.27", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-xmlrpc", ver: "5.5.9+dfsg-1ubuntu4.27", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php7.0", ver: "7.0.33-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php7.0-cgi", ver: "7.0.33-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php7.0-cli", ver: "7.0.33-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php7.0-fpm", ver: "7.0.33-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php7.0-mbstring", ver: "7.0.33-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php7.0-xmlrpc", ver: "7.0.33-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

