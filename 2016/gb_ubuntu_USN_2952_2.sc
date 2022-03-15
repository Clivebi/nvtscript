if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842722" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-06 15:29:38 +0530 (Fri, 06 May 2016)" );
	script_cve_id( "CVE-2014-9767", "CVE-2015-8835", "CVE-2016-3185", "CVE-2015-8838", "CVE-2016-1903", "CVE-2016-2554", "CVE-2016-3141", "CVE-2016-3142" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for php5 USN-2952-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php5'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2952-1 fixed vulnerabilities in PHP.
  One of the backported patches caused a regression in the PHP Soap client.
  This update fixes the problem.

  We apologize for the inconvenience.

  Original advisory details:

  It was discovered that the PHP Zip extension incorrectly handled
  directories when processing certain zip files. A remote attacker could
  possibly use this issue to create arbitrary directories. (CVE-2014-9767)
  It was discovered that the PHP Soap client incorrectly validated data
  types. A remote attacker could use this issue to cause PHP to crash,
  resulting in a denial of service, or possibly execute arbitrary code.
  (CVE-2015-8835, CVE-2016-3185)
  It was discovered that the PHP MySQL native driver incorrectly handled TLS
  connections to MySQL databases. A man in the middle attacker could possibly
  use this issue to downgrade and snoop on TLS connections. This
  vulnerability is known as BACKRONYM. (CVE-2015-8838)
  It was discovered that PHP incorrectly handled the imagerotate function. A
  remote attacker could use this issue to cause PHP to crash, resulting in a
  denial of service, or possibly obtain sensitive information. This issue
  only applied to Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2016-1903)
  Hans Jerry Illikainen discovered that the PHP phar extension incorrectly
  handled certain tar archives. A remote attacker could use this issue to
  cause PHP to crash, resulting in a denial of service, or possibly execute
  arbitrary code. (CVE-2016-2554)
  It was discovered that the PHP WDDX extension incorrectly handled certain
  malformed XML data. A remote attacker could possibly use this issue to
  cause PHP to crash, resulting in a denial of service, or possibly execute
  arbitrary code. (CVE-2016-3141)
  It was discovered that the PHP phar extension incorrectly handled certain
  zip files. A remote attacker could use this issue to cause PHP to crash,
  resulting in a denial of service, or possibly obtain sensitive information.
  (CVE-2016-3142)
  It was discovered that the PHP libxml_disable_entity_loader() setting was
  shared between threads. When running under PHP-FPM, this could result in
  XML external entity injection and entity expansion issues. This issue only
  applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (No CVE number)
  It was discovered that the PHP openssl_random_pseudo_bytes() function did
  not return cryptographically strong pseudo-random bytes. (No CVE number)
  It was discovered that the PHP Fileinfo component incorrectly handled
  certain magic files. An attacker could use this issue to cause PHP to
  crash, resulting in a denial of service, or possibly execute arbitrary
  code. (CVE number pending)
  It was disc ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "php5 on Ubuntu 15.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2952-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2952-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU15\\.10" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.6.11+dfsg-1ubuntu3.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.6.11+dfsg-1ubuntu3.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.6.11+dfsg-1ubuntu3.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.6.11+dfsg-1ubuntu3.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-gd", ver: "5.6.11+dfsg-1ubuntu3.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-mysqlnd", ver: "5.6.11+dfsg-1ubuntu3.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-snmp", ver: "5.6.11+dfsg-1ubuntu3.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

