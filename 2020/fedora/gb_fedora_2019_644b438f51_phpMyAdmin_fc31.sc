if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877201" );
	script_version( "2021-07-19T11:00:51+0000" );
	script_cve_id( "CVE-2019-12922" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-19 11:00:51 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-28 18:15:00 +0000 (Sat, 28 Sep 2019)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:31:30 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for phpMyAdmin FEDORA-2019-644b438f51" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-644b438f51" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PBLBE6CSC2ZLINIRBUU5XBLXYVBTF3KA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the FEDORA-2019-644b438f51 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "phpMyAdmin is a tool written in PHP intended to handle the administration of
MySQL over the World Wide Web. Most frequently used operations are supported
by the user interface (managing databases, tables, fields, relations, indexes,
users, permissions), while you still have the ability to directly execute any
SQL statement.

Features include an intuitive web interface, support for most MySQL features
(browse and drop databases, tables, views, fields and indexes, create, copy,
drop, rename and alter databases, tables, fields and indexes, maintenance
server, databases and tables, with proposals on server configuration, execute,
edit and bookmark any SQL-statement, even batch-queries, manage MySQL users
and privileges, manage stored procedures and triggers), import data from CSV
and SQL, export data to various formats: CSV, SQL, XML, PDF, OpenDocument Text
and Spreadsheet, Word, Excel, LATEX and others, administering multiple servers,
creating PDF graphics of your database layout, creating complex queries using
Query-by-example (QBE), searching globally in a database or a subset of it,
transforming stored data into any format using a set of predefined functions,
like displaying BLOB-data as image or download-link and much more..." );
	script_tag( name: "affected", value: "'phpMyAdmin' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "phpMyAdmin", rpm: "phpMyAdmin~4.9.1~1.fc31", rls: "FC31" ) )){
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

