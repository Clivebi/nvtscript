if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853283" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2020-0543", "CVE-2020-15563", "CVE-2020-15565", "CVE-2020-15566", "CVE-2020-15567" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-19 03:01:22 +0000 (Sun, 19 Jul 2020)" );
	script_name( "openSUSE: Security Advisory for xen (openSUSE-SU-2020:0985-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:0985-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00031.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the openSUSE-SU-2020:0985-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes the following issues:

  - CVE-2020-15563: Fixed inverted code paths in x86 dirty VRAM tracking
  (bsc#1173377).

  - CVE-2020-15565: Fixed insufficient cache write-back under VT-d
  (bsc#1173378).

  - CVE-2020-15566: Fixed incorrect error handling in event channel port
  allocation (bsc#1173376).

  - CVE-2020-15567: Fixed non-atomic modification of live EPT PTE
  (bsc#1173380).

  - CVE-2020-0543: Special Register Buffer Data Sampling (SRBDS) aka
  'CrossTalk' (bsc#1172205).

  Additional upstream bug fixes (bsc#1027519)

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-985=1" );
	script_tag( name: "affected", value: "'xen' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit-debuginfo", rpm: "xen-libs-32bit-debuginfo~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-xendomains-wait-disk", rpm: "xen-tools-xendomains-wait-disk~4.13.1_04~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

