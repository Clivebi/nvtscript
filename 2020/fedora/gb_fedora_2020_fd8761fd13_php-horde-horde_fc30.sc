if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877717" );
	script_version( "2020-04-30T08:51:29+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-30 08:51:29 +0000 (Thu, 30 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-30 03:14:27 +0000 (Thu, 30 Apr 2020)" );
	script_name( "Fedora: Security Advisory for php-horde-horde (FEDORA-2020-fd8761fd13)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2020-fd8761fd13" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Q6N6TLDK5FTNWJCRZ747I7E276UVRIUV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-horde-horde'
  package(s) announced via the FEDORA-2020-fd8761fd13 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Horde Application Framework is a flexible, modular, general-purpose web
application framework written in PHP. It provides an extensive array of
components that are targeted at the common problems and tasks involved in
developing modern web applications. It is the basis for a large number of
production-level web applications, notably the Horde Groupware suites. For
more information on Horde or the Horde Groupware suites." );
	script_tag( name: "affected", value: "'php-horde-horde' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "php-horde-horde", rpm: "php-horde-horde~5.2.22~1.fc30", rls: "FC30" ) )){
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

