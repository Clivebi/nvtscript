if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878003" );
	script_version( "2020-06-30T06:18:22+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-06-30 06:18:22 +0000 (Tue, 30 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-25 03:05:31 +0000 (Thu, 25 Jun 2020)" );
	script_name( "Fedora: Security Advisory for php-horde-horde (FEDORA-2020-01d7b8b690)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-01d7b8b690" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UG52JNKM3CQPMPCHMZAUZ47C2BS2BDVP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-horde-horde'
  package(s) announced via the FEDORA-2020-01d7b8b690 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Horde Application Framework is a flexible, modular, general-purpose web
application framework written in PHP. It provides an extensive array of
components that are targeted at the common problems and tasks involved in
developing modern web applications. It is the basis for a large number of
production-level web applications, notably the Horde Groupware suites." );
	script_tag( name: "affected", value: "'php-horde-horde' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "php-horde-horde", rpm: "php-horde-horde~5.2.23~1.fc31", rls: "FC31" ) )){
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

