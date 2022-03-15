if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853351" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2020-14344" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-04 18:15:00 +0000 (Fri, 04 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-08-13 03:00:52 +0000 (Thu, 13 Aug 2020)" );
	script_name( "openSUSE: Security Advisory for libX11 (openSUSE-SU-2020:1182-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1182-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00024.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libX11'
  package(s) announced via the openSUSE-SU-2020:1182-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libX11 fixes the following issues:

  - Fixed XIM client heap overflows (CVE-2020-14344, bsc#1174628).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1182=1" );
	script_tag( name: "affected", value: "'libX11' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libX11-6", rpm: "libX11-6~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-6-debuginfo", rpm: "libX11-6-debuginfo~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-debugsource", rpm: "libX11-debugsource~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-devel", rpm: "libX11-devel~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-xcb1", rpm: "libX11-xcb1~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-xcb1-debuginfo", rpm: "libX11-xcb1-debuginfo~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-6-32bit", rpm: "libX11-6-32bit~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-6-32bit-debuginfo", rpm: "libX11-6-32bit-debuginfo~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-devel-32bit", rpm: "libX11-devel-32bit~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-xcb1-32bit", rpm: "libX11-xcb1-32bit~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-xcb1-32bit-debuginfo", rpm: "libX11-xcb1-32bit-debuginfo~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-data", rpm: "libX11-data~1.6.5~lp152.5.6.1", rls: "openSUSELeap15.2" ) )){
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

