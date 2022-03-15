if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842904" );
	script_version( "2021-09-20T11:27:24+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:27:24 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-10-05 05:43:33 +0200 (Wed, 05 Oct 2016)" );
	script_cve_id( "CVE-2016-7124", "CVE-2016-7125", "CVE-2016-7127", "CVE-2016-7128", "CVE-2016-7129", "CVE-2016-7130", "CVE-2016-7131", "CVE-2016-7132", "CVE-2016-7413", "CVE-2016-7133", "CVE-2016-7134", "CVE-2016-7411", "CVE-2016-7412", "CVE-2016-7414", "CVE-2016-7416", "CVE-2016-7417", "CVE-2016-7418" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for php7.0 USN-3095-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php7.0'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Taoguang Chen discovered that PHP incorrectly
  handled certain invalid objects when unserializing data. A remote attacker could
  use this issue to cause PHP to crash, resulting in a denial of service, or possibly
  execute arbitrary code. (CVE-2016-7124)

Taoguang Chen discovered that PHP incorrectly handled invalid session
names. A remote attacker could use this issue to inject arbitrary session
data. (CVE-2016-7125)

It was discovered that PHP incorrectly handled certain gamma values in the
imagegammacorrect function. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-7127)

It was discovered that PHP incorrectly handled certain crafted TIFF image
thumbnails. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly expose sensitive information.
(CVE-2016-7128)

It was discovered that PHP incorrectly handled unserializing certain
wddxPacket XML documents. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-7129, CVE-2016-7130, CVE-2016-7131,
CVE-2016-7132, CVE-2016-7413)

It was discovered that PHP incorrectly handled certain memory operations. A
remote attacker could use this issue to cause PHP to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 16.04 LTS. (CVE-2016-7133)

It was discovered that PHP incorrectly handled long strings in curl_escape
calls. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 16.04 LTS. (CVE-2016-7134)

Taoguang Chen discovered that PHP incorrectly handled certain failures when
unserializing data. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2016-7411)

It was discovered that PHP incorrectly handled certain flags in the MySQL
driver. Malicious remote MySQL servers could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-7412)

It was discovered that PHP incorrectly handled ZIP file signature
verification when processing a PHAR archive. A remote attacker could use
this issue to cause PHP to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-7414)

It was discovered that PH ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "php7.0 on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3095-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3095-1/" );
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
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.5.9+dfsg-1ubuntu4.20", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.5.9+dfsg-1ubuntu4.20", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.5.9+dfsg-1ubuntu4.20", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-curl", ver: "5.5.9+dfsg-1ubuntu4.20", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.5.9+dfsg-1ubuntu4.20", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-gd", ver: "5.5.9+dfsg-1ubuntu4.20", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-mysqlnd", ver: "5.5.9+dfsg-1ubuntu4.20", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.3.10-1ubuntu3.25", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.3.10-1ubuntu3.25", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.3.10-1ubuntu3.25", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-curl", ver: "5.3.10-1ubuntu3.25", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.3.10-1ubuntu3.25", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-gd", ver: "5.3.10-1ubuntu3.25", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-mysqlnd", ver: "5.3.10-1ubuntu3.25", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php7.0", ver: "7.0.8-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php7.0-cgi", ver: "7.0.8-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php7.0-cli", ver: "7.0.8-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php7.0-curl", ver: "7.0.8-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php7.0-fpm", ver: "7.0.8-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php7.0-gd", ver: "7.0.8-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php7.0-mysql", ver: "7.0.8-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

