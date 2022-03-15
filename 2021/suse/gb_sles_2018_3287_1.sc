if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3287.1" );
	script_cve_id( "CVE-2018-10915" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:35 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-17 19:15:00 +0000 (Mon, 17 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3287-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3287-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183287-1/" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/current/static/release-9-4-19.html" );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/1851/" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/current/static/release-9-4-18.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql94' package(s) announced via the SUSE-SU-2018:3287-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql94 fixes the following issues:

postgresql was updated to 9.4.19:

 [link moved to references]
 * CVE-2018-10915, bsc#1104199: Fix failure to reset libpq's state fully
 between connection attempts.

postgresql was updated to 9.4.18:
[link moved to references]

[link moved to references] A
 dump/restore is not required for those running 9.4.X. However, if the
 function marking mistakes mentioned in the first changelog entry below
 affect you, you will want to take steps to correct your database
 catalogs." );
	script_tag( name: "affected", value: "'postgresql94' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~9.4.19~0.23.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit", rpm: "libpq5-32bit~9.4.19~0.23.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~9.4.19~0.23.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94", rpm: "postgresql94~9.4.19~0.23.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-contrib", rpm: "postgresql94-contrib~9.4.19~0.23.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-docs", rpm: "postgresql94-docs~9.4.19~0.23.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-server", rpm: "postgresql94-server~9.4.19~0.23.19.1", rls: "SLES11.0SP4" ) )){
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

