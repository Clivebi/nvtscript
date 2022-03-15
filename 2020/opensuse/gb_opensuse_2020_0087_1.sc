if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853013" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2019-15691", "CVE-2019-15692", "CVE-2019-15693", "CVE-2019-15694", "CVE-2019-15695" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-21 22:15:00 +0000 (Tue, 21 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-27 09:19:03 +0000 (Mon, 27 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for tigervnc (openSUSE-SU-2020:0087_1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0087-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00039.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tigervnc'
  package(s) announced via the openSUSE-SU-2020:0087-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tigervnc fixes the following issues:

  - CVE-2019-15691: Fixed a use-after-return due to incorrect usage of stack
  memory in ZRLEDecoder (bsc#1159856).

  - CVE-2019-15692: Fixed a heap-based buffer overflow in CopyRectDecode
  (bsc#1160250).

  - CVE-2019-15693: Fixed a heap-based buffer overflow in
  TightDecoder::FilterGradient (bsc#1159858).

  - CVE-2019-15694: Fixed a heap-based buffer overflow, caused by improper
  error handling in processing MemOutStream (bsc#1160251).

  - CVE-2019-15695: Fixed a stack-based buffer overflow, which could be
  triggered from CMsgReader::readSetCursor (bsc#1159860).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-87=1" );
	script_tag( name: "affected", value: "'tigervnc' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "tigervnc-x11vnc", rpm: "tigervnc-x11vnc~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc-java", rpm: "xorg-x11-Xvnc-java~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc-novnc", rpm: "xorg-x11-Xvnc-novnc~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libXvnc-devel", rpm: "libXvnc-devel~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libXvnc1", rpm: "libXvnc1~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libXvnc1-debuginfo", rpm: "libXvnc1-debuginfo~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tigervnc", rpm: "tigervnc~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tigervnc-debuginfo", rpm: "tigervnc-debuginfo~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tigervnc-debugsource", rpm: "tigervnc-debugsource~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc", rpm: "xorg-x11-Xvnc~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc-debuginfo", rpm: "xorg-x11-Xvnc-debuginfo~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc-module", rpm: "xorg-x11-Xvnc-module~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc-module-debuginfo", rpm: "xorg-x11-Xvnc-module-debuginfo~1.9.0~lp151.4.3.1", rls: "openSUSELeap15.1" ) )){
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

