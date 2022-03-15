if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1398.1" );
	script_cve_id( "CVE-2018-13785", "CVE-2019-7317" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:24 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1398-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1398-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191398-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpng16' package(s) announced via the SUSE-SU-2019:1398-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libpng16 fixes the following issues:

Security issues fixed:
CVE-2019-7317: Fixed a use-after-free vulnerability, triggered when
 png_image_free() was called under png_safe_execute (bsc#1124211).

CVE-2018-13785: Fixed a wrong calculation of row_factor in the
 png_check_chunk_length function in pngrutil.c, which could haved
 triggered and integer overflow and result in an divide-by-zero while
 processing a crafted PNG file, leading to a denial of service
 (bsc#1100687)" );
	script_tag( name: "affected", value: "'libpng16' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15." );
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
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16", rpm: "libpng16-16~1.6.34~3.9.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16-32bit", rpm: "libpng16-16-32bit~1.6.34~3.9.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16-32bit-debuginfo", rpm: "libpng16-16-32bit-debuginfo~1.6.34~3.9.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16-debuginfo", rpm: "libpng16-16-debuginfo~1.6.34~3.9.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-compat-devel", rpm: "libpng16-compat-devel~1.6.34~3.9.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-debugsource", rpm: "libpng16-debugsource~1.6.34~3.9.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-devel", rpm: "libpng16-devel~1.6.34~3.9.1", rls: "SLES15.0" ) )){
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

