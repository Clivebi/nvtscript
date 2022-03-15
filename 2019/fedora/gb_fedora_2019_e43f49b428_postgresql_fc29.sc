if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876608" );
	script_version( "2021-09-01T12:01:34+0000" );
	script_cve_id( "CVE-2019-10164" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 12:01:34 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-02 14:34:00 +0000 (Fri, 02 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-07-26 02:21:50 +0000 (Fri, 26 Jul 2019)" );
	script_name( "Fedora Update for postgresql FEDORA-2019-e43f49b428" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-e43f49b428" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TTKEHXGDXYYD6WYDIIQJP4GDQJSENDJK" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'postgresql' package(s) announced via the FEDORA-2019-e43f49b428 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "PostgreSQL is an advanced Object-Relational
  database management system (DBMS). The base postgresql package contains the
  client programs that you&#39, ll need to access a PostgreSQL DBMS server,
  as well as HTML documentation for the whole system.  These client programs
  can be located on the same machine as the PostgreSQL server, or on a remote
  machine that accesses a PostgreSQL server over a network connection.
  The PostgreSQL server can be found in the postgresql-server sub-package." );
	script_tag( name: "affected", value: "'postgresql' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "postgresql", rpm: "postgresql~10.9~1.fc29", rls: "FC29" ) )){
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

