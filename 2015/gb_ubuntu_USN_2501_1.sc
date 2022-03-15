if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842094" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-18 05:41:59 +0100 (Wed, 18 Feb 2015)" );
	script_cve_id( "CVE-2014-8142", "CVE-2015-0231", "CVE-2014-9427", "CVE-2014-9652", "CVE-2015-0232", "CVE-2015-1351", "CVE-2015-1352" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for php5 USN-2501-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php5'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Stefan Esser discovered that PHP
incorrectly handled unserializing objects. A remote attacker could use this
issue to cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2014-8142, CVE-2015-0231)

Brian Carpenter discovered that the PHP CGI component incorrectly handled
invalid files. A local attacker could use this issue to obtain sensitive
information, or possibly execute arbitrary code. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2014-9427)

It was discovered that PHP incorrectly handled certain pascal strings in
the fileinfo extension. A remote attacker could possibly use this issue to
cause PHP to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2014-9652)

Alex Eubanks discovered that PHP incorrectly handled EXIF data in JPEG
images. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2015-0232)

It was discovered that the PHP opcache component incorrectly handled
memory. A remote attacker could possibly use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-1351)

It was discovered that the PHP PostgreSQL database extension incorrectly
handled certain pointers. A remote attacker could possibly use this issue
to cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 14.04 LTS and
Ubuntu 14.10. (CVE-2015-1352)" );
	script_tag( name: "affected", value: "php5 on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2501-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2501-1/" );
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
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.5.12+dfsg-2ubuntu4.2", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.5.12+dfsg-2ubuntu4.2", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.5.12+dfsg-2ubuntu4.2", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.5.12+dfsg-2ubuntu4.2", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-pgsql", ver: "5.5.12+dfsg-2ubuntu4.2", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.5.9+dfsg-1ubuntu4.6", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.5.9+dfsg-1ubuntu4.6", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.5.9+dfsg-1ubuntu4.6", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.5.9+dfsg-1ubuntu4.6", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-pgsql", ver: "5.5.9+dfsg-1ubuntu4.6", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.3.10-1ubuntu3.16", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.3.10-1ubuntu3.16", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.3.10-1ubuntu3.16", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.3.10-1ubuntu3.16", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-pgsql", ver: "5.3.10-1ubuntu3.16", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

