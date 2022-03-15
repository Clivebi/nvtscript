if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853479" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2020-25595", "CVE-2020-25596", "CVE-2020-25597", "CVE-2020-25598", "CVE-2020-25599", "CVE-2020-25600", "CVE-2020-25601", "CVE-2020-25602", "CVE-2020-25603", "CVE-2020-25604" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-11 06:15:00 +0000 (Wed, 11 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-10-05 03:00:48 +0000 (Mon, 05 Oct 2020)" );
	script_name( "openSUSE: Security Advisory for xen (openSUSE-SU-2020:1608-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1608-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00008.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the openSUSE-SU-2020:1608-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes the following issues:

  - CVE-2020-25602: Fixed an issue where there was a crash when handling
  guest access to MSR_MISC_ENABLE was thrown (bsc#1176339, XSA-333)

  - CVE-2020-25598: Added a missing unlock in XENMEM_acquire_resource error
  path (bsc#1176341, XSA-334)

  - CVE-2020-25604: Fixed a race condition when migrating timers between x86
  HVM vCPU-s (bsc#1176343, XSA-336)

  - CVE-2020-25595: Fixed an issue where PCI passthrough code was reading
  back hardware registers (bsc#1176344, XSA-337)

  - CVE-2020-25597: Fixed an issue where a valid event channels may not turn
  invalid (bsc#1176346, XSA-338)

  - CVE-2020-25596: Fixed a potential denial of service in x86 pv guest
  kernel via SYSENTER (bsc#1176345, XSA-339)

  - CVE-2020-25603: Fixed an issue due to  missing barriers when
  accessing/allocating an event channel (bsc#1176347, XSA-340)

  - CVE-2020-25600: Fixed out of bounds event channels available to 32-bit
  x86 domains (bsc#1176348, XSA-342)

  - CVE-2020-25599: Fixed race conditions with evtchn_reset()
  (bsc#1176349, XSA-343)

  - CVE-2020-25601: Fixed an issue due to lack of preemption in
  evtchn_reset() / evtchn_destroy() (bsc#1176350, XSA-344)

  - Various other fixes (bsc#1027519)

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1608=1" );
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
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit-debuginfo", rpm: "xen-libs-32bit-debuginfo~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-xendomains-wait-disk", rpm: "xen-tools-xendomains-wait-disk~4.13.1_08~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
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

