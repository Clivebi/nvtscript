if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876687" );
	script_version( "2019-12-12T12:03:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-12 12:03:08 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-08-16 02:24:22 +0000 (Fri, 16 Aug 2019)" );
	script_name( "Fedora Update for mariadb-connector-odbc FEDORA-2019-60befaed69" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-60befaed69" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FEHG7T4DYFSVBHXIBQHHSJOLP3GOLGGE" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb-connector-odbc'
  package(s) announced via the FEDORA-2019-60befaed69 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MariaDB Connector/ODBC is a standardized, LGPL licensed database driver using
the industry standard Open Database Connectivity (ODBC) API. It supports ODBC
Standard 3.5, can be used as a drop-in replacement for MySQL Connector/ODBC,
and it supports both Unicode and ANSI modes." );
	script_tag( name: "affected", value: "'mariadb-connector-odbc' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "mariadb-connector-odbc", rpm: "mariadb-connector-odbc~3.1.2~1.fc30", rls: "FC30" ) )){
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

