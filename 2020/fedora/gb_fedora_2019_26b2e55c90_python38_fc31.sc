if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877336" );
	script_version( "2020-01-13T11:49:13+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-01-13 11:49:13 +0000 (Mon, 13 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:38:18 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for python38 FEDORA-2019-26b2e55c90" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-26b2e55c90" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SO6GH6IQTGFXAD4S7PMOAXALGL6RQCSJ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python38'
  package(s) announced via the FEDORA-2019-26b2e55c90 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Python 3.8 package for developers.

This package exists to allow developers to test their code against a newer
version of Python. This is not a full Python stack and if you wish to run
your applications with Python 3.8, update your Fedora to a newer
version once Python 3.8 is stable." );
	script_tag( name: "affected", value: "'python38' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "python38", rpm: "python38~3.8.1~1.fc31", rls: "FC31" ) )){
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

