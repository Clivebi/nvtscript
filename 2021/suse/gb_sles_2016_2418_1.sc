if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2418.1" );
	script_cve_id( "CVE-2016-5423", "CVE-2016-5424" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2418-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2418-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162418-1/" );
	script_xref( name: "URL", value: "http://www.postgresql.org/docs/9.4/static/release-9-4-9.html" );
	script_xref( name: "URL", value: "http://www.postgresql.org/docs/9.4/static/release-9-4-8.html" );
	script_xref( name: "URL", value: "http://www.postgresql.org/docs/9.4/static/release-9-4-7.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql94' package(s) announced via the SUSE-SU-2016:2418-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql94 to version 9.4.9 fixes the several issues.
These security issues were fixed:
- CVE-2016-5423: CASE/WHEN with inlining can cause untrusted pointer
 dereference (bsc#993454).
- CVE-2016-5424: Fix client programs' handling of special characters in
 database and role names (bsc#993453).
For the non-security issues please refer to
- [link moved to references]
- [link moved to references]
- [link moved to references]" );
	script_tag( name: "affected", value: "'postgresql94' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4, SUSE Manager 2.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~9.4.9~0.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit", rpm: "libpq5-32bit~9.4.9~0.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~9.4.9~0.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94", rpm: "postgresql94~9.4.9~0.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-contrib", rpm: "postgresql94-contrib~9.4.9~0.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-docs", rpm: "postgresql94-docs~9.4.9~0.19.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-server", rpm: "postgresql94-server~9.4.9~0.19.1", rls: "SLES11.0SP4" ) )){
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

