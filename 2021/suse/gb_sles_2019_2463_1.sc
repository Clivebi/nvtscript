if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2463.1" );
	script_cve_id( "CVE-2019-13616", "CVE-2019-13626" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:16 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-05 11:27:00 +0000 (Mon, 05 Apr 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2463-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2463-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192463-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'SDL2' package(s) announced via the SUSE-SU-2019:2463-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for SDL2 fixes the following issues:

Security issues fixed:
CVE-2019-13616: Fixed heap-based buffer over-read in BlitNtoN in
 video/SDL_blit_N.c (bsc#1141844).

CVE-2019-13626: Fixed integer overflow in IMA_ADPCM_decode() in
 audio/SDL_wave.c (bsc#1142031)." );
	script_tag( name: "affected", value: "'SDL2' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Desktop Applications 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "SDL2-debugsource", rpm: "SDL2-debugsource~2.0.8~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-2_0-0", rpm: "libSDL2-2_0-0~2.0.8~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-2_0-0-debuginfo", rpm: "libSDL2-2_0-0-debuginfo~2.0.8~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-devel", rpm: "libSDL2-devel~2.0.8~3.15.1", rls: "SLES15.0" ) )){
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "SDL2-debugsource", rpm: "SDL2-debugsource~2.0.8~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-2_0-0", rpm: "libSDL2-2_0-0~2.0.8~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-2_0-0-debuginfo", rpm: "libSDL2-2_0-0-debuginfo~2.0.8~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-devel", rpm: "libSDL2-devel~2.0.8~3.15.1", rls: "SLES15.0SP1" ) )){
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

