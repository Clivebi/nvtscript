if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3606.2" );
	script_cve_id( "CVE-2018-17096", "CVE-2018-17097", "CVE-2018-17098" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-08 19:35:00 +0000 (Thu, 08 Nov 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3606-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3606-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183606-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'soundtouch' package(s) announced via the SUSE-SU-2018:3606-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for soundtouch fixes the following issues:
CVE-2018-17098: The WavFileBase class allowed remote attackers to cause
 a denial of service (heap corruption from size inconsistency) or
 possibly have unspecified other impact, as demonstrated by SoundStretch.
 (bsc#1108632)

CVE-2018-17097: The WavFileBase class allowed remote attackers to cause
 a denial of service (double free) or possibly have unspecified other
 impact, as demonstrated by SoundStretch. (double free) (bsc#1108631)

CVE-2018-17096: The BPMDetect class allowed remote attackers to cause a
 denial of service (assertion failure and application exit), as
 demonstrated by SoundStretch. (bsc#1108630)" );
	script_tag( name: "affected", value: "'soundtouch' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Workstation Extension 12-SP4." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libSoundTouch0", rpm: "libSoundTouch0~1.7.1~5.6.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSoundTouch0-debuginfo", rpm: "libSoundTouch0-debuginfo~1.7.1~5.6.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "soundtouch-debuginfo", rpm: "soundtouch-debuginfo~1.7.1~5.6.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "soundtouch-debugsource", rpm: "soundtouch-debugsource~1.7.1~5.6.1", rls: "SLES12.0SP4" ) )){
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

