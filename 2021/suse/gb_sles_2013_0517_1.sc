if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.0517.1" );
	script_cve_id( "CVE-2013-0255" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-20 01:29:00 +0000 (Fri, 20 Oct 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:0517-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:0517-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20130517-1/" );
	script_xref( name: "URL", value: "http://www.postgresql.org/about/news/1446/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'PostgreSQL' package(s) announced via the SUSE-SU-2013:0517-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "PostgreSQL has been updated to version 9.1.8 which fixes various bugs and one security issue.

The security issue fixed in this release, CVE-2013-0255,
allowed a previously authenticated user to crash the server by calling an internal function with invalid arguments. This issue was discovered by the independent security researcher Sumit Soni this week and reported via Secunia SVCRP, and we are grateful for their efforts in making PostgreSQL more secure.

More information can be found at

[link moved to references]

Security Issue reference:

 * CVE-2013-0255
>" );
	script_tag( name: "affected", value: "'PostgreSQL' package(s) on SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP2." );
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~9.1.8~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit", rpm: "libpq5-32bit~9.1.8~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~9.1.8~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-x86", rpm: "libpq5-x86~9.1.8~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql", rpm: "postgresql~8.3.23~0.4.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-contrib", rpm: "postgresql-contrib~8.3.23~0.4.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-docs", rpm: "postgresql-docs~8.3.23~0.4.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-server", rpm: "postgresql-server~8.3.23~0.4.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql91", rpm: "postgresql91~9.1.8~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql91-contrib", rpm: "postgresql91-contrib~9.1.8~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql91-docs", rpm: "postgresql91-docs~9.1.8~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql91-server", rpm: "postgresql91-server~9.1.8~0.5.1", rls: "SLES11.0SP2" ) )){
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

