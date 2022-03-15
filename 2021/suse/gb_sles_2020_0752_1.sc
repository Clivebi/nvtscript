if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0752.1" );
	script_cve_id( "CVE-2020-1720" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:06 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0752-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0752-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200752-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql10' package(s) announced via the SUSE-SU-2020:0752-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql10 fixes the following issues:

PostgreSQL was updated to version 10.12.

Security issue fixed:

CVE-2020-1720: Fixed a missing authorization check in the ALTER ...
 DEPENDS ON extension (bsc#1163985)." );
	script_tag( name: "affected", value: "'postgresql10' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Server Applications 15-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo", rpm: "libpq5-debuginfo~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10", rpm: "postgresql10~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-debuginfo", rpm: "postgresql10-debuginfo~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-debugsource", rpm: "postgresql10-debugsource~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo", rpm: "libecpg6-debuginfo~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-contrib", rpm: "postgresql10-contrib~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-contrib-debuginfo", rpm: "postgresql10-contrib-debuginfo~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-devel", rpm: "postgresql10-devel~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-devel-debuginfo", rpm: "postgresql10-devel-debuginfo~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-docs", rpm: "postgresql10-docs~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plperl", rpm: "postgresql10-plperl~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plperl-debuginfo", rpm: "postgresql10-plperl-debuginfo~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plpython", rpm: "postgresql10-plpython~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plpython-debuginfo", rpm: "postgresql10-plpython-debuginfo~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-pltcl", rpm: "postgresql10-pltcl~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-pltcl-debuginfo", rpm: "postgresql10-pltcl-debuginfo~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-server", rpm: "postgresql10-server~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-server-debuginfo", rpm: "postgresql10-server-debuginfo~10.12~8.9.1", rls: "SLES15.0SP1" ) )){
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

