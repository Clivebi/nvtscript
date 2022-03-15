if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0748.1" );
	script_cve_id( "CVE-2018-18584", "CVE-2018-18585" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:29 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-12 20:52:00 +0000 (Wed, 12 May 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0748-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0748-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190748-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmspack' package(s) announced via the SUSE-SU-2019:0748-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libmspack fixes the following issues:

Security issues fixed:
CVE-2018-18584: The CAB block input buffer was one byte too small for
 the maximal Quantum block, leading to an out-of-bounds write.
 (bsc#1113038)

CVE-2018-18585: chmd_read_headers accepted a filename that has '\\0' as
 its first or second character (such as the '/\\0' name). (bsc#1113039)

Fix off-by-one bounds check on CHM PMGI/PMGL chunk numbers and reject
 empty filenames." );
	script_tag( name: "affected", value: "'libmspack' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15." );
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
	if(!isnull( res = isrpmvuln( pkg: "libmspack-debugsource", rpm: "libmspack-debugsource~0.6~3.3.11", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmspack-devel", rpm: "libmspack-devel~0.6~3.3.11", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmspack0", rpm: "libmspack0~0.6~3.3.11", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmspack0-debuginfo", rpm: "libmspack0-debuginfo~0.6~3.3.11", rls: "SLES15.0" ) )){
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

