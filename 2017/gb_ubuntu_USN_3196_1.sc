if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843051" );
	script_version( "2021-09-14T09:01:51+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 09:01:51 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-15 05:49:31 +0100 (Wed, 15 Feb 2017)" );
	script_cve_id( "CVE-2014-9912", "CVE-2016-7478", "CVE-2016-7479", "CVE-2016-9137", "CVE-2016-9934", "CVE-2016-9935", "CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160", "CVE-2016-10161" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-07 03:00:00 +0000 (Sat, 07 Jan 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for php5 USN-3196-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php5'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that PHP incorrectly
  handled certain arguments to the locale_get_display_name function. A remote
  attacker could use this issue to cause PHP to crash, resulting in a denial of
  service, or possibly execute arbitrary code. (CVE-2014-9912)

It was discovered that PHP incorrectly handled certain invalid objects when
unserializing data. A remote attacker could use this issue to cause PHP to
hang, resulting in a denial of service. (CVE-2016-7478)

It was discovered that PHP incorrectly handled certain invalid objects when
unserializing data. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-7479)

It was discovered that PHP incorrectly handled certain invalid objects when
unserializing data. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only applied to Ubuntu 14.04 LTS. (CVE-2016-9137)

It was discovered that PHP incorrectly handled unserializing certain
wddxPacket XML documents. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service. (CVE-2016-9934)

It was discovered that PHP incorrectly handled unserializing certain
wddxPacket XML documents. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-9935)

It was discovered that PHP incorrectly handled certain EXIF data. A remote
attacker could use this issue to cause PHP to crash, resulting in a denial
of service. (CVE-2016-10158)

It was discovered that PHP incorrectly handled certain PHAR archives. A
remote attacker could use this issue to cause PHP to crash or consume
resources, resulting in a denial of service. (CVE-2016-10159)

It was discovered that PHP incorrectly handled certain PHAR archives. A
remote attacker could use this issue to cause PHP to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2016-10160)

It was discovered that PHP incorrectly handled certain invalid objects when
unserializing data. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service. (CVE-2016-10161)" );
	script_tag( name: "affected", value: "php5 on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3196-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3196-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.5.9+dfsg-1ubuntu4.21", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.5.9+dfsg-1ubuntu4.21", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.5.9+dfsg-1ubuntu4.21", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.5.9+dfsg-1ubuntu4.21", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.3.10-1ubuntu3.26", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.3.10-1ubuntu3.26", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.3.10-1ubuntu3.26", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.3.10-1ubuntu3.26", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

