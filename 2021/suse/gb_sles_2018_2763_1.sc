if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2763.1" );
	script_cve_id( "CVE-2018-15120" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:37 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-14 15:41:00 +0000 (Wed, 14 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2763-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2763-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182763-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pango' package(s) announced via the SUSE-SU-2018:2763-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for pango fixes the following issues:

Security issue fixed:
CVE-2018-15120: Fixed a denial of service when parsing emoji
 (bsc#1103877)" );
	script_tag( name: "affected", value: "'pango' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Desktop Applications 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libpango-1_0-0", rpm: "libpango-1_0-0~1.40.14~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpango-1_0-0-debuginfo", rpm: "libpango-1_0-0-debuginfo~1.40.14~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pango-debugsource", rpm: "pango-debugsource~1.40.14~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pango-devel", rpm: "pango-devel~1.40.14~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-Pango-1_0", rpm: "typelib-1_0-Pango-1_0~1.40.14~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpango-1_0-0-32bit", rpm: "libpango-1_0-0-32bit~1.40.14~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpango-1_0-0-32bit-debuginfo", rpm: "libpango-1_0-0-32bit-debuginfo~1.40.14~3.3.1", rls: "SLES15.0" ) )){
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

