if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878052" );
	script_version( "2021-07-19T02:00:45+0000" );
	script_cve_id( "CVE-2018-16516" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-19 02:00:45 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-08 03:15:00 +0000 (Wed, 08 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-08 03:29:19 +0000 (Wed, 08 Jul 2020)" );
	script_name( "Fedora: Security Advisory for python-flask-admin (FEDORA-2020-e8f384af5f)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-e8f384af5f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZU2VKULURVXEU4YFTLMBQGYMPSXQ4MBN" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-flask-admin'
  package(s) announced via the FEDORA-2020-e8f384af5f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Flask-Admin is advanced, extensible and simple to use administrative interface
building extension for Flask framework.

It comes with batteries included: model scaffolding for SQLAlchemy,
MongoEngine, MongoDB and Peewee ORMs, simple file management interface
and a lot of usage samples.

You&#39, re not limited by the default functionality - instead of providing simple
scaffolding for the ORM models, Flask-Admin provides tools that can be used to
construct administrative interfaces of any complexity, using a consistent look
and feel." );
	script_tag( name: "affected", value: "'python-flask-admin' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "python-flask-admin", rpm: "python-flask-admin~1.5.6~1.fc32", rls: "FC32" ) )){
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
