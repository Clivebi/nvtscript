if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853812" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-2145", "CVE-2021-2250", "CVE-2021-2264", "CVE-2021-2266", "CVE-2021-2279", "CVE-2021-2280", "CVE-2021-2281", "CVE-2021-2282", "CVE-2021-2283", "CVE-2021-2284", "CVE-2021-2285", "CVE-2021-2286", "CVE-2021-2287", "CVE-2021-2291", "CVE-2021-2296", "CVE-2021-2297", "CVE-2021-2306", "CVE-2021-2309", "CVE-2021-2310", "CVE-2021-2312" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-26 13:14:00 +0000 (Mon, 26 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-05-15 03:01:33 +0000 (Sat, 15 May 2021)" );
	script_name( "openSUSE: Security Advisory for virtualbox (openSUSE-SU-2021:0723-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0723-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/H2VYFQN75RCOBQFQCIU4LU7E32CGO4SK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2021:0723-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for virtualbox fixes the following issues:

     virtualbox was updated to 6.1.22 (released April 29 2021 by Oracle)

     This is a maintenance release. The following items were fixed and/or added:

  - VMM: Improved performance of 64-bit Windows and Solaris guests when
       Hyper-V is used on recent Windows 10 hosts

  - VMM: Fixed frequent crashes of 64-bit Windows Vista and Server 2003
       guests when Hyper-V is used

  - GUI: Fixed regression where user was not able to save unset default
       shortcuts (bug #20305)

  - Storage: Fixed regression in LsiLogic SAS controller emulation caused VM
       crash (bug #20323)

  - Linux Guest Additions: Fixed issue when it was not possible to run
       executables from mounted share (bug #20320)

  - Fixes for CVE-2021-2145 CVE-2021-2250 CVE-2021-2264 CVE-2021-2266
       CVE-2021-2279 CVE-2021-2280 CVE-2021-2281 CVE-2021-2282 CVE-2021-2283
       CVE-2021-2284 CVE-2021-2285 CVE-2021-2286 CVE-2021-2287 CVE-2021-2291
       CVE-2021-2296 CVE-2021-2297 CVE-2021-2306 CVE-2021-2309 CVE-2021-2310
       CVE-2021-2312

  - Version bump to (released April 20 2021 by Oracle) File
       'virtualbox-kmp-files-leap' is deleted.

  - Use distconfdir for xinitrc.d files on TW

  - Improve autostart security boo#1182918." );
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
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-desktop-icons", rpm: "virtualbox-guest-desktop-icons~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-source", rpm: "virtualbox-guest-source~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-host-source", rpm: "virtualbox-host-source~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-virtualbox", rpm: "python3-virtualbox~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-virtualbox-debuginfo", rpm: "python3-virtualbox-debuginfo~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox", rpm: "virtualbox~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-debuginfo", rpm: "virtualbox-debuginfo~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-debugsource", rpm: "virtualbox-debugsource~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-devel", rpm: "virtualbox-devel~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-tools", rpm: "virtualbox-guest-tools~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-tools-debuginfo", rpm: "virtualbox-guest-tools-debuginfo~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-x11", rpm: "virtualbox-guest-x11~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-x11-debuginfo", rpm: "virtualbox-guest-x11-debuginfo~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-debugsource", rpm: "virtualbox-kmp-debugsource~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-default", rpm: "virtualbox-kmp-default~6.1.22_k5.3.18_lp152.75~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-default-debuginfo", rpm: "virtualbox-kmp-default-debuginfo~6.1.22_k5.3.18_lp152.75~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-preempt", rpm: "virtualbox-kmp-preempt~6.1.22_k5.3.18_lp152.75~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-preempt-debuginfo", rpm: "virtualbox-kmp-preempt-debuginfo~6.1.22_k5.3.18_lp152.75~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-qt", rpm: "virtualbox-qt~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-qt-debuginfo", rpm: "virtualbox-qt-debuginfo~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-vnc", rpm: "virtualbox-vnc~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-websrv", rpm: "virtualbox-websrv~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-websrv-debuginfo", rpm: "virtualbox-websrv-debuginfo~6.1.22~lp152.2.24.2", rls: "openSUSELeap15.2" ) )){
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

