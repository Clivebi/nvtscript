if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.2149.1" );
	script_cve_id( "CVE-2020-1720" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:2149-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1|SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:2149-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20202149-1/" );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/2038/" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/10/release-10-13.html" );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/2011/" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/10/release-10-12.html" );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/1994/" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/10/release-10-11.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql10 and postgresql12 ' package(s) announced via the SUSE-SU-2020:2149-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql10 and postgresql12 fixes the following issues:

postgresql10 was updated to 10.13 (bsc#1171924).

 [link moved to references]
[link moved to references]

postgresql10 was updated to 10.12 (CVE-2020-1720, bsc#1163985)

[link moved to references]

[link moved to references]

postgresql10 was updated to 10.11:

[link moved to references]

[link moved to references]


postgresql12 was updated to 12.3 (bsc#1171924).

Bug Fixes and Improvements:

Several fixes for GENERATED columns, including an issue where it was
 possible to crash or corrupt data in a table when the output of the
 generated column was the exact copy of a physical column on the table,
 e.g. if the expression called a function which could return its own
 input.

Several fixes for ALTER TABLE, including ensuring the SET STORAGE
 directive is propagated to a table's indexes.

Fix a potential race condition when using DROP OWNED BY while another
 session is deleting the same objects.

Allow for a partition to be detached when it has inherited ROW triggers.

Several fixes for REINDEX CONCURRENTLY, particularly with issues when a
 REINDEX CONCURRENTLY operation fails.

Fix crash when COLLATE is applied to an uncollatable type in a partition
 bound expression.

Fix performance regression in floating point overflow/underflow
 detection.

Several fixes for full text search, particularly with phrase searching.

Fix query-lifespan memory leak for a set-returning function used in a
 query's FROM clause.

Several reporting fixes for the output of VACUUM VERBOSE.

Allow input of type circle to accept the format (x,y),r, which is
 specified in the documentation.

Allow for the get_bit() and set_bit() functions to not fail on bytea
 strings longer than 256MB.

Avoid premature recycling of WAL segments during crash recovery, which
 could lead to WAL segments being recycled before being archived.

Avoid attempting to fetch nonexistent WAL files from archive storage
 during recovery by skipping irrelevant timelines.

Several fixes for logical replication and replication slots.

Fix several race conditions in synchronous standby management, including
 one that occurred when changing the synchronous_standby_names setting.

Several fixes for GSSAPI support, include a fix for a memory leak that
 occurred when using GSSAPI encryption.

Ensure that members of the pg_read_all_stats role can read all
 statistics views.

Fix performance regression in information_schema.triggers view.

Fix memory leak in libpq when using sslmode=verify-full.

Fix crash in psql when attempting to re-establish a failed connection.

Allow tab-completion of the filename argument to \\gx command in psql.

Add pg_dump support for ALTER ... DEPENDS ON EXTENSION.

Several other fixes for pg_dump, which ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'postgresql10 and postgresql12 ' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1, SUSE Linux Enterprise Module for Server Applications 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit", rpm: "libpq5-32bit~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit-debuginfo", rpm: "libpq5-32bit-debuginfo~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo", rpm: "libpq5-debuginfo~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql", rpm: "postgresql~12.0.1~8.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12", rpm: "postgresql12~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-debuginfo", rpm: "postgresql12-debuginfo~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-debugsource", rpm: "postgresql12-debugsource~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-test", rpm: "postgresql-test~12.0.1~8.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo", rpm: "libecpg6-debuginfo~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-contrib", rpm: "postgresql-contrib~12.0.1~8.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-devel", rpm: "postgresql-devel~12.0.1~8.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-docs", rpm: "postgresql-docs~12.0.1~8.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-plperl", rpm: "postgresql-plperl~12.0.1~8.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-plpython", rpm: "postgresql-plpython~12.0.1~8.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-pltcl", rpm: "postgresql-pltcl~12.0.1~8.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-server", rpm: "postgresql-server~12.0.1~8.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-server-devel", rpm: "postgresql-server-devel~12.0.1~8.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-contrib", rpm: "postgresql12-contrib~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-contrib-debuginfo", rpm: "postgresql12-contrib-debuginfo~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-devel", rpm: "postgresql12-devel~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-devel-debuginfo", rpm: "postgresql12-devel-debuginfo~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-docs", rpm: "postgresql12-docs~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plperl", rpm: "postgresql12-plperl~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plperl-debuginfo", rpm: "postgresql12-plperl-debuginfo~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plpython", rpm: "postgresql12-plpython~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plpython-debuginfo", rpm: "postgresql12-plpython-debuginfo~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-pltcl", rpm: "postgresql12-pltcl~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-pltcl-debuginfo", rpm: "postgresql12-pltcl-debuginfo~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server", rpm: "postgresql12-server~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server-debuginfo", rpm: "postgresql12-server-debuginfo~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server-devel", rpm: "postgresql12-server-devel~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server-devel-debuginfo", rpm: "postgresql12-server-devel-debuginfo~12.3~3.8.1", rls: "SLES15.0SP1" ) )){
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo", rpm: "libecpg6-debuginfo~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo", rpm: "libpq5-debuginfo~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql", rpm: "postgresql~12.0.1~8.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-contrib", rpm: "postgresql-contrib~12.0.1~8.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-devel", rpm: "postgresql-devel~12.0.1~8.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-docs", rpm: "postgresql-docs~12.0.1~8.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-plperl", rpm: "postgresql-plperl~12.0.1~8.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-plpython", rpm: "postgresql-plpython~12.0.1~8.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-pltcl", rpm: "postgresql-pltcl~12.0.1~8.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-server", rpm: "postgresql-server~12.0.1~8.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10", rpm: "postgresql10~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-contrib", rpm: "postgresql10-contrib~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-contrib-debuginfo", rpm: "postgresql10-contrib-debuginfo~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-debuginfo", rpm: "postgresql10-debuginfo~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-debugsource", rpm: "postgresql10-debugsource~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-devel", rpm: "postgresql10-devel~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-devel-debuginfo", rpm: "postgresql10-devel-debuginfo~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-docs", rpm: "postgresql10-docs~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plperl", rpm: "postgresql10-plperl~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plperl-debuginfo", rpm: "postgresql10-plperl-debuginfo~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plpython", rpm: "postgresql10-plpython~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plpython-debuginfo", rpm: "postgresql10-plpython-debuginfo~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-pltcl", rpm: "postgresql10-pltcl~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-pltcl-debuginfo", rpm: "postgresql10-pltcl-debuginfo~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-server", rpm: "postgresql10-server~10.13~4.22.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-server-debuginfo", rpm: "postgresql10-server-debuginfo~10.13~4.22.4", rls: "SLES15.0" ) )){
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

