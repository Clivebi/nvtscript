if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852860" );
	script_version( "2021-08-13T12:00:53+0000" );
	script_cve_id( "CVE-2019-17113" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 12:00:53 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-02 01:15:00 +0000 (Sun, 02 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:38:18 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for libopenmpt (openSUSE-SU-2019:2306-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2306-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-10/msg00035.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libopenmpt'
  package(s) announced via the openSUSE-SU-2019:2306-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libopenmpt to version 0.3.19 fixes the following issues:

  - CVE-2019-17113: Fixed a buffer overflow in ModPlug_InstrumentName and
  ModPlug_SampleName (bsc#1153102).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2306=1" );
	script_tag( name: "affected", value: "'libopenmpt' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "libmodplug-devel", rpm: "libmodplug-devel~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmodplug1", rpm: "libmodplug1~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmodplug1-debuginfo", rpm: "libmodplug1-debuginfo~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt-debugsource", rpm: "libopenmpt-debugsource~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt-devel", rpm: "libopenmpt-devel~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt0", rpm: "libopenmpt0~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt0-debuginfo", rpm: "libopenmpt0-debuginfo~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt_modplug1", rpm: "libopenmpt_modplug1~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt_modplug1-debuginfo", rpm: "libopenmpt_modplug1-debuginfo~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openmpt123", rpm: "openmpt123~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openmpt123-debuginfo", rpm: "openmpt123-debuginfo~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmodplug1-32bit", rpm: "libmodplug1-32bit~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmodplug1-32bit-debuginfo", rpm: "libmodplug1-32bit-debuginfo~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt0-32bit", rpm: "libopenmpt0-32bit~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt0-32bit-debuginfo", rpm: "libopenmpt0-32bit-debuginfo~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt_modplug1-32bit", rpm: "libopenmpt_modplug1-32bit~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenmpt_modplug1-32bit-debuginfo", rpm: "libopenmpt_modplug1-32bit-debuginfo~0.3.19~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
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

