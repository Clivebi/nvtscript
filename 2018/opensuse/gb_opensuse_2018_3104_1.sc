if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851933" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-10-13 06:54:28 +0200 (Sat, 13 Oct 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for postgresql10 (openSUSE-SU-2018:3104-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql10'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for brings postgresql10 version 10.5 to openSUSE Leap 42.3.
  (FATE#325659 bnc#1108308)

  This release marks the change of the versioning scheme for PostgreSQL to a
  'x.y' format. This means the next minor releases of PostgreSQL will be
  10.1, 10.2, ... and the next major release will be 11.

  * Logical Replication

  Logical replication extends the current replication features of PostgreSQL
  with the ability to send modifications on a per-database and per-table
  level to different PostgreSQL databases. Users can now fine-tune the data
  replicated to various database clusters and will have the ability to
  perform zero-downtime upgrades to future major PostgreSQL versions.

  * Declarative Table Partitioning

  Table partitioning has existed for years in PostgreSQL but required a user
  to maintain a nontrivial set of rules and triggers for the partitioning to
  work. PostgreSQL 10 introduces a table partitioning syntax that lets users
  easily create and maintain range and list partitioned tables.

  * Improved Query Parallelism

  PostgreSQL 10 provides better support for parallelized queries by allowing
  more parts of the query execution process to be parallelized. Improvements
  include additional types of data scans that are parallelized as well as
  optimizations when the data is recombined, such as pre-sorting. These
  enhancements allow results to be returned more quickly.

  * Quorum Commit for Synchronous Replication

  PostgreSQL 10 introduces quorum commit for synchronous replication, which
  allows for flexibility in how a primary database receives acknowledgement
  that changes were successfully written to remote replicas.


  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1148=1" );
	script_tag( name: "affected", value: "postgresql10 on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:3104-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00023.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo", rpm: "libecpg6-debuginfo~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo", rpm: "libpq5-debuginfo~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10", rpm: "postgresql10~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-contrib", rpm: "postgresql10-contrib~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-contrib-debuginfo", rpm: "postgresql10-contrib-debuginfo~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-debuginfo", rpm: "postgresql10-debuginfo~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-debugsource", rpm: "postgresql10-debugsource~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-devel", rpm: "postgresql10-devel~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-devel-debuginfo", rpm: "postgresql10-devel-debuginfo~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-libs-debugsource", rpm: "postgresql10-libs-debugsource~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plperl", rpm: "postgresql10-plperl~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plperl-debuginfo", rpm: "postgresql10-plperl-debuginfo~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plpython", rpm: "postgresql10-plpython~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plpython-debuginfo", rpm: "postgresql10-plpython-debuginfo~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-pltcl", rpm: "postgresql10-pltcl~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-pltcl-debuginfo", rpm: "postgresql10-pltcl-debuginfo~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-server", rpm: "postgresql10-server~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-server-debuginfo", rpm: "postgresql10-server-debuginfo~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-test", rpm: "postgresql10-test~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-32bit", rpm: "libecpg6-32bit~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo-32bit", rpm: "libecpg6-debuginfo-32bit~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit", rpm: "libpq5-32bit~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo-32bit", rpm: "libpq5-debuginfo-32bit~10.5~2.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-init", rpm: "postgresql-init~10~16.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-docs", rpm: "postgresql10-docs~10.5~2.1", rls: "openSUSELeap42.3" ) )){
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

