if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853756" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2021-2074", "CVE-2021-2129" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-27 01:40:00 +0000 (Wed, 27 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:02:58 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for virtualbox (openSUSE-SU-2021:0165-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0165-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UOZDUDAVWBPMEHQXT2I4NXOMGVCWB5BM" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2021:0165-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for virtualbox fixes the following issues:

     Version update to 6.1.18 (released January 19 2021)

     This is a maintenance release. The following items were fixed and/or added:

  - Nested VM: Fixed hangs when executing SMP nested-guests under certain
       conditions on Intel hosts (bug #19315, #19561)

  - OCI integration: Cloud Instance parameters parsing is improved on import
       (bug #19156)

  - Network: UDP checksum offloading in e1000 no longer produces zero
       checksums (bug #19930)

  - Network: Fixed Host-Only Ethernet Adapter DHCP, guest os can not get IP
       on host resume (bug #19620)

  - NAT: Fixed mss parameter handing (bug #15256)

  - macOS host: Multiple optimizations for BigSur

  - Audio: Fixed issues with audio playback after host goes to sleep (bug
       #18594)

  - Documentation: Some content touch-up and table formatting fixes

  - Linux host and guest: Support kernel version 5.10 (bug #20055)

  - Solaris host: Fix regression breaking VGA text mode since version 6.1.0

  - Guest Additions: Fixed a build failure affecting CentOS 8.2-2004 and
       later (bug #20091)

  - Guest Additions: Fixed a build failure affecting Linux kernels 3.2.0
       through 3.2.50 (bug #20006)

  - Guest Additions: Fixed a VM segfault on copy with shared clipboard with
       X11 (bug #19226)

  - Shared Folder: Fixed error with remounting on Linux guests

  - Fixes CVE-2021-2074, boo#1181197 and CVE-2021-2129, boo#1181198.

  - Disable build of guest modules. These are included in recent kernels

  - Fix additional mouse control dialog issues." );
	script_tag( name: "affected", value: "'virtualbox' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-desktop-icons", rpm: "virtualbox-guest-desktop-icons~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-host-source", rpm: "virtualbox-host-source~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-virtualbox", rpm: "python3-virtualbox~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-virtualbox-debuginfo", rpm: "python3-virtualbox-debuginfo~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox", rpm: "virtualbox~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-debuginfo", rpm: "virtualbox-debuginfo~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-debugsource", rpm: "virtualbox-debugsource~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-devel", rpm: "virtualbox-devel~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-tools", rpm: "virtualbox-guest-tools~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-tools-debuginfo", rpm: "virtualbox-guest-tools-debuginfo~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-x11", rpm: "virtualbox-guest-x11~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-x11-debuginfo", rpm: "virtualbox-guest-x11-debuginfo~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-debugsource", rpm: "virtualbox-kmp-debugsource~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-default", rpm: "virtualbox-kmp-default~6.1.18_k5.3.18_lp152.60~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-default-debuginfo", rpm: "virtualbox-kmp-default-debuginfo~6.1.18_k5.3.18_lp152.60~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-preempt", rpm: "virtualbox-kmp-preempt~6.1.18_k5.3.18_lp152.60~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-preempt-debuginfo", rpm: "virtualbox-kmp-preempt-debuginfo~6.1.18_k5.3.18_lp152.60~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-qt", rpm: "virtualbox-qt~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-qt-debuginfo", rpm: "virtualbox-qt-debuginfo~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-vnc", rpm: "virtualbox-vnc~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-websrv", rpm: "virtualbox-websrv~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-websrv-debuginfo", rpm: "virtualbox-websrv-debuginfo~6.1.18~lp152.2.11.1", rls: "openSUSELeap15.2" ) )){
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

