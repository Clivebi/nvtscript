if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877009" );
	script_version( "2021-09-01T09:01:32+0000" );
	script_cve_id( "CVE-2019-3465" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 09:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-17 03:31:48 +0000 (Sun, 17 Nov 2019)" );
	script_name( "Fedora Update for php-robrichards-xmlseclibs3 FEDORA-2019-be01267416" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-be01267416" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ESKJTWLE7QZBQ3EKMYXKMBQG3JDEJWM6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-robrichards-xmlseclibs3'
  package(s) announced via the FEDORA-2019-be01267416 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "xmlseclibs is a library written in PHP for working with XML Encryption and
Signatures.

Autoloader: /usr/share/php/RobRichards/XMLSecLibs3/autoload.php" );
	script_tag( name: "affected", value: "'php-robrichards-xmlseclibs3' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "php-robrichards-xmlseclibs3", rpm: "php-robrichards-xmlseclibs3~3.0.4~1.fc29", rls: "FC29" ) )){
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

