if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883275" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2020-13692" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-15 17:14:00 +0000 (Mon, 15 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-08-08 03:01:11 +0000 (Sat, 08 Aug 2020)" );
	script_name( "CentOS: Security Advisory for postgresql-jdbc (CESA-2020:3284)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2020:3284" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-August/035794.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql-jdbc'
  package(s) announced via the CESA-2020:3284 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "PostgreSQL is an advanced object-relational database management system. The
postgresql-jdbc package includes the .jar files needed for Java programs to
access a PostgreSQL database.

Security Fix(es):

  * postgresql-jdbc: XML external entity (XXE) vulnerability in PgSQLXML
(CVE-2020-13692)

This update introduces a backwards incompatible change required to resolve
this issue. Refer to the Red Hat Knowledgebase article 5266441 linked to in
the References section for information on how to re-enable the old insecure
behavior.

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'postgresql-jdbc' package(s) on CentOS 6." );
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
if(release == "CentOS6"){
	if(!isnull( res = isrpmvuln( pkg: "postgresql-jdbc", rpm: "postgresql-jdbc~8.4.704~4.el6_10", rls: "CentOS6" ) )){
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

