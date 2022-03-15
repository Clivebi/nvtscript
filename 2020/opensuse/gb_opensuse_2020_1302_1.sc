if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853397" );
	script_version( "2021-08-13T12:00:53+0000" );
	script_cve_id( "CVE-2020-14345", "CVE-2020-14346", "CVE-2020-14347" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 12:00:53 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-15 19:15:00 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-09-02 11:51:04 +0530 (Wed, 02 Sep 2020)" );
	script_name( "openSUSE: Security Advisory for xorg-x11-server (openSUSE-SU-2020:1302-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1302-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00075.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11-server'
  package(s) announced via the openSUSE-SU-2020:1302-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xorg-x11-server fixes the following issues:

  - CVE-2020-14347: Leak of uninitialized heap memory from the X server to
  clients on pixmap allocation (bsc#1174633, ZDI-CAN-11426).

  - CVE-2020-14346: XIChangeHierarchy Integer Underflow Privilege Escalation
  Vulnerability (bsc#1174638, ZDI-CAN-11429).

  - CVE-2020-14345: XKB out-of-bounds access privilege escalation
  vulnerability (bsc#1174635, ZDI-CAN-11428).

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1302=1" );
	script_tag( name: "affected", value: "'xorg-x11-server' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server", rpm: "xorg-x11-server~1.20.3~lp152.8.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-debuginfo", rpm: "xorg-x11-server-debuginfo~1.20.3~lp152.8.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-debugsource", rpm: "xorg-x11-server-debugsource~1.20.3~lp152.8.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-extra", rpm: "xorg-x11-server-extra~1.20.3~lp152.8.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-extra-debuginfo", rpm: "xorg-x11-server-extra-debuginfo~1.20.3~lp152.8.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-sdk", rpm: "xorg-x11-server-sdk~1.20.3~lp152.8.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-source", rpm: "xorg-x11-server-source~1.20.3~lp152.8.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-wayland", rpm: "xorg-x11-server-wayland~1.20.3~lp152.8.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-wayland-debuginfo", rpm: "xorg-x11-server-wayland-debuginfo~1.20.3~lp152.8.3.1", rls: "openSUSELeap15.2" ) )){
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

