if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878311" );
	script_version( "2020-09-18T13:18:38+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-09-18 13:18:38 +0000 (Fri, 18 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-17 03:08:05 +0000 (Thu, 17 Sep 2020)" );
	script_name( "Fedora: Security Advisory for python-flask-cors (FEDORA-2020-863fc5c796)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-863fc5c796" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/W6LRZKPHG7HIU3HBB7SOBUHO5QBUHXXW" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-flask-cors'
  package(s) announced via the FEDORA-2020-863fc5c796 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A Flask extension for handling Cross Origin Resource Sharing (CORS),
making cross-origin AJAX possible." );
	script_tag( name: "affected", value: "'python-flask-cors' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-flask-cors", rpm: "python-flask-cors~3.0.9~1.fc31", rls: "FC31" ) )){
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

