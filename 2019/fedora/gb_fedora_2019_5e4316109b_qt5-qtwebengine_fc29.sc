if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876780" );
	script_version( "2019-12-12T12:03:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-12 12:03:08 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-09-09 02:23:09 +0000 (Mon, 09 Sep 2019)" );
	script_name( "Fedora Update for qt5-qtwebengine FEDORA-2019-5e4316109b" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-5e4316109b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M7HJAVMZYMWDG6RC42GOUDABHSCIXHSL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qt5-qtwebengine'
  package(s) announced via the FEDORA-2019-5e4316109b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Qt5 - QtWebEngine components." );
	script_tag( name: "affected", value: "'qt5-qtwebengine' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtwebengine", rpm: "qt5-qtwebengine~5.12.4~5.fc29", rls: "FC29" ) )){
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

