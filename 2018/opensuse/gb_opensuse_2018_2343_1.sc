if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851857" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-17 05:57:40 +0200 (Fri, 17 Aug 2018)" );
	script_cve_id( "CVE-2018-14522", "CVE-2018-14523" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-17 21:29:00 +0000 (Wed, 17 Apr 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for aubio (openSUSE-SU-2018:2343-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aubio'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for aubio fixes the following issues:

  - CVE-2018-14522: Fixed a crash in aubio_pitch_set_unit (bsc#1102359)

  - CVE-2018-14523: Fixed a buffer overrread resulting in crash or
  information leakage in new_aubio_pitchyinfft (bsc#1102364)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-868=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-868=1" );
	script_tag( name: "affected", value: "aubio on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2343-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00052.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "aubio-debugsource", rpm: "aubio-debugsource~0.4.1~9.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aubio-tools", rpm: "aubio-tools~0.4.1~9.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aubio-tools-debuginfo", rpm: "aubio-tools-debuginfo~0.4.1~9.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaubio-devel", rpm: "libaubio-devel~0.4.1~9.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaubio4", rpm: "libaubio4~0.4.1~9.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaubio4-debuginfo", rpm: "libaubio4-debuginfo~0.4.1~9.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaubio4-32bit", rpm: "libaubio4-32bit~0.4.1~9.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaubio4-debuginfo-32bit", rpm: "libaubio4-debuginfo-32bit~0.4.1~9.9.1", rls: "openSUSELeap42.3" ) )){
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

