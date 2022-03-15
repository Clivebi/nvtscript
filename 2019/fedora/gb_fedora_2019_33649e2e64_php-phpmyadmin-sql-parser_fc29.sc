if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876502" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2019-11768", "CVE-2019-12616" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-14 04:29:00 +0000 (Fri, 14 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-15 02:10:00 +0000 (Sat, 15 Jun 2019)" );
	script_name( "Fedora Update for php-phpmyadmin-sql-parser FEDORA-2019-33649e2e64" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-33649e2e64" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZKJMYVXEDXGEGRO42T6H6VOEZJ65QPQ7" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'php-phpmyadmin-sql-parser' package(s) announced via the
  FEDORA-2019-33649e2e64 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "A validating SQL lexer and parser with a
  focus on MySQL dialect.

This library was originally developed for phpMyAdmin during
the Google Summer of Code 2015.

Autoloader: /usr/share/php/PhpMyAdmin/SqlParser/autoload.php" );
	script_tag( name: "affected", value: "'php-phpmyadmin-sql-parser' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "php-phpmyadmin-sql-parser", rpm: "php-phpmyadmin-sql-parser~4.3.2~1.fc29", rls: "FC29" ) )){
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
