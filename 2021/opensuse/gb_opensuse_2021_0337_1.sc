if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853757" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2020-25694", "CVE-2020-25695", "CVE-2020-25696" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-15 19:37:00 +0000 (Tue, 15 Dec 2020)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:02:59 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for postgresql, (openSUSE-SU-2021:0337-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0337-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IQQBNVIVAXDZCJPFZE43ZEZ3C6DSC3WG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql, '
  package(s) announced via the openSUSE-SU-2021:0337-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql, postgresql13 fixes the following issues:

     This update ships postgresql13.

     Upgrade to version 13.1:

  * CVE-2020-25695, bsc#1178666: Block DECLARE CURSOR ... WITH HOLD and
       firing of deferred triggers within index expressions and materialized
       view queries.

  * CVE-2020-25694, bsc#1178667: a) Fix usage of complex connection-string
       parameters in pg_dump, pg_restore, clusterdb, reindexdb, and vacuumdb.
       b) When psql&#x27 s \\connect command re-uses connection parameters, ensure
       that all non-overridden parameters from a previous connection string are
       re-used.

  * CVE-2020-25696, bsc#1178668: Prevent psql&#x27 s \\gset command from modifying
       specially-treated variables.

  * Fix recently-added timetz test case so it works when the USA is not
       observing daylight savings time. (obsoletes postgresql-timetz.patch)

     Initial packaging of PostgreSQL 13:

  - bsc#1178961: %ghost the symlinks to pg_config and ecpg.

     Changes in postgresql wrapper package:

  - Bump major version to 13.

  - We also transfer PostgreSQL 9.4.26 to the new package layout in
       SLE12-SP2 and newer. Reflect this in the conflict with postgresql94.

  - Also conflict with PostgreSQL versions before 9.

  - Conflicting with older versions is not limited to SLE.

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'postgresql, ' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "postgresql", rpm: "postgresql~13~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-contrib", rpm: "postgresql-contrib~13~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-devel", rpm: "postgresql-devel~13~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-docs", rpm: "postgresql-docs~13~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-llvmjit", rpm: "postgresql-llvmjit~13~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-plperl", rpm: "postgresql-plperl~13~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-plpython", rpm: "postgresql-plpython~13~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-pltcl", rpm: "postgresql-pltcl~13~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-server", rpm: "postgresql-server~13~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-server-devel", rpm: "postgresql-server-devel~13~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-test", rpm: "postgresql-test~13~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
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

