if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852719" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2018-20860", "CVE-2018-20861", "CVE-2019-14382", "CVE-2019-14383" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-29 00:15:00 +0000 (Sun, 29 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-09-29 02:01:32 +0000 (Sun, 29 Sep 2019)" );
	script_name( "openSUSE: Security Advisory for libopenmpt (openSUSE-SU-2019:2212-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2212-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00085.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libopenmpt'
  package(s) announced via the openSUSE-SU-2019:2212-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libopenmpt fixes the following issues:

  Security issues fixed:

  - CVE-2018-20861: Fixed crash with certain malformed custom tunings in
  MPTM files (bsc#1143578).

  - CVE-2018-20860: Fixed crash with malformed MED files (bsc#1143581).

  - CVE-2019-14383: Fixed J2B that allows an assertion failure during file
  parsing with debug STLs (bsc#1143584).

  - CVE-2019-14382: Fixed DSM that allows an assertion failure during file
  parsing with debug STLs (bsc#1143582).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2212=1" );
	script_tag( name: "affected", value: "'libopenmpt' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libmodplug-devel", rpm: "libmodplug-devel~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmodplug1", rpm: "libmodplug1~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmodplug1-debuginfo", rpm: "libmodplug1-debuginfo~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt-debugsource", rpm: "libopenmpt-debugsource~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt-devel", rpm: "libopenmpt-devel~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt0", rpm: "libopenmpt0~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt0-debuginfo", rpm: "libopenmpt0-debuginfo~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt_modplug1", rpm: "libopenmpt_modplug1~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt_modplug1-debuginfo", rpm: "libopenmpt_modplug1-debuginfo~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openmpt123", rpm: "openmpt123~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openmpt123-debuginfo", rpm: "openmpt123-debuginfo~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmodplug1-32bit", rpm: "libmodplug1-32bit~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmodplug1-32bit-debuginfo", rpm: "libmodplug1-32bit-debuginfo~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt0-32bit", rpm: "libopenmpt0-32bit~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt0-32bit-debuginfo", rpm: "libopenmpt0-32bit-debuginfo~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt_modplug1-32bit", rpm: "libopenmpt_modplug1-32bit~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt_modplug1-32bit-debuginfo", rpm: "libopenmpt_modplug1-32bit-debuginfo~0.3.17~lp150.7.1", rls: "openSUSELeap15.0" ) )){
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

