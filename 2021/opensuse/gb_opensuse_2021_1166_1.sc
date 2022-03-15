if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854079" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2018-13139", "CVE-2018-19432", "CVE-2018-19758", "CVE-2021-3246" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2021-08-20 06:51:55 +0000 (Fri, 20 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for libsndfile (openSUSE-SU-2021:1166-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1166-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VGFWRIIXBFCLA7GINXJUPUD7YVYB5UKO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsndfile'
  package(s) announced via the openSUSE-SU-2021:1166-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libsndfile fixes the following issues:

  - CVE-2018-13139: Fixed a stack-based buffer overflow in psf_memset in
       common.c in libsndfile 1.0.28allows remote attackers to cause a denial
       of service (application crash) or possibly have unspecified other
       impact. (bsc#1100167)

  - CVE-2018-19432: Fixed a NULL pointer dereference in the function
       sf_write_int in sndfile.c, which will lead to a denial of service.
       (bsc#1116993)

  - CVE-2021-3246: Fixed a heap buffer overflow vulnerability in
       msadpcm_decode_block. (bsc#1188540)

  - CVE-2018-19758: Fixed a heap-based buffer over-read at wav.c in
       wav_write_header in libsndfile 1.0.28 that will cause a denial of
       service. (bsc#1117954)

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'libsndfile' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libsndfile-debugsource", rpm: "libsndfile-debugsource~1.0.28~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile-devel", rpm: "libsndfile-devel~1.0.28~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile1", rpm: "libsndfile1~1.0.28~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile1-debuginfo", rpm: "libsndfile1-debuginfo~1.0.28~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile-progs", rpm: "libsndfile-progs~1.0.28~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile-progs-debuginfo", rpm: "libsndfile-progs-debuginfo~1.0.28~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile-progs-debugsource", rpm: "libsndfile-progs-debugsource~1.0.28~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile1-32bit", rpm: "libsndfile1-32bit~1.0.28~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile1-32bit-debuginfo", rpm: "libsndfile1-32bit-debuginfo~1.0.28~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
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

