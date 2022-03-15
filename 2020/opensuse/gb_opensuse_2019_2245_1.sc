if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852826" );
	script_version( "2021-08-13T14:00:52+0000" );
	script_cve_id( "CVE-2019-5736" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-13 14:00:52 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-01 20:15:00 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:33:37 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for lxc (openSUSE-SU-2019:2245-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2245-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-10/msg00007.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lxc'
  package(s) announced via the openSUSE-SU-2019:2245-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for lxc fixes the following issues:

  + seccomp: support syscall forwarding to userspace
  + add lxc.seccomp.allow_nesting
  + pidfd: Add initial support for the new pidfd api

  * Many hardening improvements.

  * Use /sys/kernel/cgroup/delegate file for cgroup v2.

  * Fix CVE-2019-5736 equivalent bug.

  - fix apparmor dropin to be compatible with LXC 3.1.0 (boo#1131762)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2245=1" );
	script_tag( name: "affected", value: "'lxc' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "lxc-bash-completion", rpm: "lxc-bash-completion~3.2.1~lp151.4.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblxc-devel", rpm: "liblxc-devel~3.2.1~lp151.4.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblxc1", rpm: "liblxc1~3.2.1~lp151.4.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblxc1-debuginfo", rpm: "liblxc1-debuginfo~3.2.1~lp151.4.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lxc", rpm: "lxc~3.2.1~lp151.4.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lxc-debuginfo", rpm: "lxc-debuginfo~3.2.1~lp151.4.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lxc-debugsource", rpm: "lxc-debugsource~3.2.1~lp151.4.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_cgfs", rpm: "pam_cgfs~3.2.1~lp151.4.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_cgfs-debuginfo", rpm: "pam_cgfs-debuginfo~3.2.1~lp151.4.5.1", rls: "openSUSELeap15.1" ) )){
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

