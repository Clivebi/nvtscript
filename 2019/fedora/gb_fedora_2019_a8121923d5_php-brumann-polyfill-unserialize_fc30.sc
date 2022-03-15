if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876534" );
	script_version( "2021-10-04T08:02:33+0000" );
	script_cve_id( "CVE-2019-11831", "CVE-2019-11830" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-04 08:02:33 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-29 16:29:00 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-06-27 02:14:04 +0000 (Thu, 27 Jun 2019)" );
	script_name( "Fedora Update for php-brumann-polyfill-unserialize FEDORA-2019-a8121923d5" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-a8121923d5" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VYU6FAW54QNQQBBB27CGXK7D4OQXQ2IP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-brumann-polyfill-unserialize'
  package(s) announced via the FEDORA-2019-a8121923d5 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Backports unserialize options introduced in PHP 7.0 to older PHP versions. This
was originally designed as a Proof of Concept for Symfony Issue.

You can use this package in projects that rely on PHP versions older than PHP
7.0. In case you are using PHP 7.0+ the original unserialize() will be used
instead." );
	script_tag( name: "affected", value: "'php-brumann-polyfill-unserialize' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "php-brumann-polyfill-unserialize", rpm: "php-brumann-polyfill-unserialize~1.0.3~1.fc30", rls: "FC30" ) )){
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

