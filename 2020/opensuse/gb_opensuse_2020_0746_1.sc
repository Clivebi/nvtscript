if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853190" );
	script_version( "2021-08-13T03:00:58+0000" );
	script_cve_id( "CVE-2019-1010305" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 03:00:58 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-23 23:15:00 +0000 (Fri, 23 Aug 2019)" );
	script_tag( name: "creation_date", value: "2020-06-01 03:00:55 +0000 (Mon, 01 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for libmspack (openSUSE-SU-2020:0746-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0746-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00068.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmspack'
  package(s) announced via the openSUSE-SU-2020:0746-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libmspack fixes the following issues:

  Security issue fixed:

  - CVE-2019-1010305: Fixed a buffer overflow triggered by a crafted chm
  file which could have led to information disclosure (bsc#1141680).

  Other issue addressed:

  - Enable build-time tests (bsc#1130489)


  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-746=1" );
	script_tag( name: "affected", value: "'libmspack' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libmspack-debugsource", rpm: "libmspack-debugsource~0.6~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmspack-devel", rpm: "libmspack-devel~0.6~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmspack0", rpm: "libmspack0~0.6~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmspack0-debuginfo", rpm: "libmspack0-debuginfo~0.6~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mspack-tools", rpm: "mspack-tools~0.6~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mspack-tools-debuginfo", rpm: "mspack-tools-debuginfo~0.6~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmspack0-32bit", rpm: "libmspack0-32bit~0.6~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmspack0-32bit-debuginfo", rpm: "libmspack0-32bit-debuginfo~0.6~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
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

