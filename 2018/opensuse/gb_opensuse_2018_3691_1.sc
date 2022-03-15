if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852122" );
	script_version( "2021-06-29T11:00:37+0000" );
	script_cve_id( "CVE-2018-17096", "CVE-2018-17097", "CVE-2018-17098" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-08 19:35:00 +0000 (Thu, 08 Nov 2018)" );
	script_tag( name: "creation_date", value: "2018-11-10 05:59:46 +0100 (Sat, 10 Nov 2018)" );
	script_name( "openSUSE: Security Advisory for soundtouch (openSUSE-SU-2018:3691-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:3691-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00004.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'soundtouch'
  package(s) announced via the openSUSE-SU-2018:3691-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for soundtouch fixes the following issues:

  - CVE-2018-17098: The WavFileBase class allowed remote attackers to cause
  a denial of service (heap corruption from size inconsistency) or
  possibly have unspecified other impact, as demonstrated by SoundStretch.
  (bsc#1108632)

  - CVE-2018-17097: The WavFileBase class allowed remote attackers to cause
  a denial of service (double free) or possibly have unspecified other
  impact, as demonstrated by SoundStretch. (double free) (bsc#1108631)

  - CVE-2018-17096: The BPMDetect class allowed remote attackers to cause a
  denial of service (assertion failure and application exit), as
  demonstrated by SoundStretch. (bsc#1108630)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1362=1" );
	script_tag( name: "affected", value: "soundtouch on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libSoundTouch0", rpm: "libSoundTouch0~1.8.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSoundTouch0-debuginfo", rpm: "libSoundTouch0-debuginfo~1.8.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "soundtouch", rpm: "soundtouch~1.8.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "soundtouch-debuginfo", rpm: "soundtouch-debuginfo~1.8.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "soundtouch-debugsource", rpm: "soundtouch-debugsource~1.8.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "soundtouch-devel", rpm: "soundtouch-devel~1.8.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSoundTouch0-32bit", rpm: "libSoundTouch0-32bit~1.8.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSoundTouch0-32bit-debuginfo", rpm: "libSoundTouch0-32bit-debuginfo~1.8.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
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

