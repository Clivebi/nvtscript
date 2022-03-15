if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852126" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_cve_id( "CVE-2018-14665" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-22 23:15:00 +0000 (Tue, 22 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-11-17 06:15:25 +0100 (Sat, 17 Nov 2018)" );
	script_name( "openSUSE: Security Advisory for xorg-x11-server (openSUSE-SU-2018:3800-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:3800-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00022.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11-server'
  package(s) announced via the openSUSE-SU-2018:3800-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xorg-x11-server fixes the following issues:

  - CVE-2018-14665: Disable -logfile and -modulepath when running with
  elevated privileges (bsc#1112020,

  Note that SUSE by default does not run with elevated privileges, so the
  default installation is not affected by this problem.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1420=1" );
	script_tag( name: "affected", value: "xorg-x11-server on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server", rpm: "xorg-x11-server~1.19.6~lp150.7.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-debuginfo", rpm: "xorg-x11-server-debuginfo~1.19.6~lp150.7.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-debugsource", rpm: "xorg-x11-server-debugsource~1.19.6~lp150.7.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-extra", rpm: "xorg-x11-server-extra~1.19.6~lp150.7.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-extra-debuginfo", rpm: "xorg-x11-server-extra-debuginfo~1.19.6~lp150.7.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-sdk", rpm: "xorg-x11-server-sdk~1.19.6~lp150.7.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-source", rpm: "xorg-x11-server-source~1.19.6~lp150.7.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-wayland", rpm: "xorg-x11-server-wayland~1.19.6~lp150.7.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-wayland-debuginfo", rpm: "xorg-x11-server-wayland-debuginfo~1.19.6~lp150.7.3.1", rls: "openSUSELeap15.0" ) )){
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

