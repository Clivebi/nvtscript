if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877011" );
	script_version( "2021-09-02T08:01:23+0000" );
	script_cve_id( "CVE-2019-3465" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 08:01:23 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-17 03:31:52 +0000 (Sun, 17 Nov 2019)" );
	script_name( "Fedora Update for php-robrichards-xmlseclibs FEDORA-2019-dc90bf093b" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-dc90bf093b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XBSSRV5Q7JFCYO46A3EN624UZ4KXFQ2M" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-robrichards-xmlseclibs'
  package(s) announced via the FEDORA-2019-dc90bf093b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "xmlseclibs is a library written in PHP for working with XML Encryption and
Signatures.

NOTE: php-mcrypt will not be automatically installed as a dependency of this
package so it will need to be 'manually' installed if it is required --
specifically for the following XMLSecurityKey encryption types:

  - XMLSecurityKey::AES128_CBC

  - XMLSecurityKey::AES192_CBC

  - XMLSecurityKey::AES256_CBC

  - XMLSecurityKey::TRIPLEDES_CBC

Autoloader: /usr/share/php/RobRichards/XMLSecLibs/autoload.php" );
	script_tag( name: "affected", value: "'php-robrichards-xmlseclibs' package(s) on Fedora 30." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "php-robrichards-xmlseclibs", rpm: "php-robrichards-xmlseclibs~2.1.1~1.fc30", rls: "FC30" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

