if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876690" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2019-2510", "CVE-2019-2537", "CVE-2019-2614", "CVE-2019-2627", "CVE-2019-2628" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-16 02:24:33 +0000 (Fri, 16 Aug 2019)" );
	script_name( "Fedora Update for mariadb FEDORA-2019-60befaed69" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-60befaed69" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PNJK7AE5I5R4PFE34GSKG6Q2JJDHDWO7" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb'
  package(s) announced via the FEDORA-2019-60befaed69 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MariaDB is a community developed branch of MySQL - a multi-user, multi-threaded
SQL database server. It is a client/server implementation consisting of
a server daemon (mysqld) and many different client programs and libraries.
The base package contains the standard MariaDB/MySQL client programs and
generic MySQL files." );
	script_tag( name: "affected", value: "'mariadb' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "mariadb", rpm: "mariadb~10.3.17~1.fc30", rls: "FC30" ) )){
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

