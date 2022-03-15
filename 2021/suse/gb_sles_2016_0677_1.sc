if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.0677.1" );
	script_cve_id( "CVE-2007-4772", "CVE-2015-5288", "CVE-2015-5289", "CVE-2016-0766", "CVE-2016-0773" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:08 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:0677-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:0677-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20160677-1/" );
	script_xref( name: "URL", value: "http://www.postgresql.org/docs/9.4/static/release-9-4-6.html" );
	script_xref( name: "URL", value: "http://www.postgresql.org/docs/current/static/release-9-4-5.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql94' package(s) announced via the SUSE-SU-2016:0677-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql94 fixes the following issues:
- Security and bugfix release 9.4.6:
 * *** IMPORTANT *** Users of version 9.4 will need to reindex any
 jsonb_path_ops indexes they have created, in order to fix a persistent
 issue with missing index entries.
 * Fix infinite loops and buffer-overrun problems in regular expressions
 (CVE-2016-0773, bsc#966436).
 * Fix regular-expression compiler to handle loops of constraint arcs
 (CVE-2007-4772).
 * Prevent certain PL/Java parameters from being set by non-superusers
 (CVE-2016-0766, bsc#966435).
 * Fix many issues in pg_dump with specific object types
 * Prevent over-eager pushdown of HAVING clauses for GROUPING SETS
 * Fix deparsing error with ON CONFLICT ... WHERE clauses
 * Fix tableoid errors for postgres_fdw
 * Prevent floating-point exceptions in pgbench
 * Make \\det search Foreign Table names consistently
 * Fix quoting of domain constraint names in pg_dump
 * Prevent putting expanded objects into Const nodes
 * Allow compile of PL/Java on Windows
 * Fix 'unresolved symbol' errors in PL/Python execution
 * Allow Python2 and Python3 to be used in the same database
 * Add support for Python 3.5 in PL/Python
 * Fix issue with subdirectory creation during initdb
 * Make pg_ctl report status correctly on Windows
 * Suppress confusing error when using pg_receivexlog with older servers
 * Multiple documentation corrections and additions
 * Fix erroneous hash calculations in gin_extract_jsonb_path()
- For the full release notse, see:
 [link moved to references]
- Security and bugfix release 9.4.5:
 * CVE-2015-5289, bsc#949670: json or jsonb input values constructed from
 arbitrary user input can crash the PostgreSQL server and cause a
 denial of service.
 * CVE-2015-5288, bsc#949669: The crypt() function included with the
 optional pgCrypto extension could be exploited to read a few
 additional bytes of memory. No working exploit for this issue has been
 developed.
- For the full release notse, see:
 [link moved to references]
- Relax dependency on libpq to major version." );
	script_tag( name: "affected", value: "'postgresql94' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~9.4.6~0.14.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit", rpm: "libpq5-32bit~9.4.6~0.14.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~9.4.6~0.14.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94", rpm: "postgresql94~9.4.6~0.14.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-contrib", rpm: "postgresql94-contrib~9.4.6~0.14.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-docs", rpm: "postgresql94-docs~9.4.6~0.14.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-server", rpm: "postgresql94-server~9.4.6~0.14.3", rls: "SLES11.0SP4" ) )){
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

