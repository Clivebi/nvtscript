if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877708" );
	script_version( "2020-04-21T09:23:28+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-21 09:23:28 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-19 03:18:59 +0000 (Sun, 19 Apr 2020)" );
	script_name( "Fedora: Security Advisory for cacti (FEDORA-2020-c1745db1aa)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-c1745db1aa" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/C53DLO7F6OUR25UOT5JWXZ225O4A2QPT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cacti'
  package(s) announced via the FEDORA-2020-c1745db1aa advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Cacti is a complete frontend to RRDTool. It stores all of the
necessary information to create graphs and populate them with
data in a MySQL database. The frontend is completely PHP
driven." );
	script_tag( name: "affected", value: "'cacti' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "cacti", rpm: "cacti~1.2.11~1.fc31", rls: "FC31" ) )){
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
