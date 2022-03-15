if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853168" );
	script_version( "2021-08-13T12:00:53+0000" );
	script_cve_id( "CVE-2020-0034" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 12:00:53 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-23 00:15:00 +0000 (Sat, 23 May 2020)" );
	script_tag( name: "creation_date", value: "2020-05-23 03:00:51 +0000 (Sat, 23 May 2020)" );
	script_name( "openSUSE: Security Advisory for libvpx (openSUSE-SU-2020:0680-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0680-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00048.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvpx'
  package(s) announced via the openSUSE-SU-2020:0680-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libvpx fixes the following issues:

  - CVE-2020-0034: Fixed an out-of-bounds read on truncated key frames
  (bsc#1166066).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-680=1" );
	script_tag( name: "affected", value: "'libvpx' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libvpx-debugsource", rpm: "libvpx-debugsource~1.6.1~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvpx-devel", rpm: "libvpx-devel~1.6.1~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvpx4", rpm: "libvpx4~1.6.1~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvpx4-debuginfo", rpm: "libvpx4-debuginfo~1.6.1~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vpx-tools", rpm: "vpx-tools~1.6.1~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vpx-tools-debuginfo", rpm: "vpx-tools-debuginfo~1.6.1~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvpx4-32bit", rpm: "libvpx4-32bit~1.6.1~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvpx4-32bit-debuginfo", rpm: "libvpx4-32bit-debuginfo~1.6.1~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
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

