if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876372" );
	script_version( "2021-10-04T08:02:33+0000" );
	script_cve_id( "CVE-2019-11831", "CVE-2019-11830" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-04 08:02:33 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-29 16:29:00 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-05-17 02:12:21 +0000 (Fri, 17 May 2019)" );
	script_name( "Fedora Update for php-typo3-phar-stream-wrapper FEDORA-2019-4d93cf2b34" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-4d93cf2b34" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AUEXS4HRI4XZ2DTZMWAVQBYBTFSJ34AR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-typo3-phar-stream-wrapper'
  package(s) announced via the FEDORA-2019-4d93cf2b34 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Interceptors for PHP&#39, s native phar:// stream handling.

Autoloader: /usr/share/php/TYPO3/PharStreamWrapper/autoload.php" );
	script_tag( name: "affected", value: "'php-typo3-phar-stream-wrapper' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "php-typo3-phar-stream-wrapper", rpm: "php-typo3-phar-stream-wrapper~3.1.1~1.fc28", rls: "FC28" ) )){
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

