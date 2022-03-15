if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853560" );
	script_version( "2021-08-13T03:00:58+0000" );
	script_cve_id( "CVE-2020-16846", "CVE-2020-17490", "CVE-2020-25592" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 03:00:58 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-30 13:29:00 +0000 (Tue, 30 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-11-06 04:01:17 +0000 (Fri, 06 Nov 2020)" );
	script_name( "openSUSE: Security Advisory for salt (openSUSE-SU-2020:1833-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1833-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00018.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'salt'
  package(s) announced via the openSUSE-SU-2020:1833-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for salt fixes the following issues:

  - Properly validate eauth credentials and tokens on SSH calls made by Salt
  API (bsc#1178319, bsc#1178362, bsc#1178361, CVE-2020-25592,
  CVE-2020-17490, CVE-2020-16846)

  - Fix disk.blkid to avoid unexpected keyword argument '__pub_user'.
  (bsc#1177867)

  - Ensure virt.update stop_on_reboot is updated with its default value.

  - Do not break package building for systemd OSes.

  - Drop wrong mock from chroot unit test.

  - Support systemd versions with dot. (bsc#1176294)

  - Fix for grains.test_core unit test.

  - Fix file/directory user and group ownership containing UTF-8 characters.
  (bsc#1176024)

  - Several changes to virtualization:

  * Fix virt update when cpu and memory are changed.

  * Memory Tuning GSoC.

  * Properly fix memory setting regression in virt.update.

  * Expose libvirt on_reboot in virt states.

  - Support transactional systems (MicroOS).

  - zypperpkg module ignores retcode 104 for search(). (bsc#1159670)

  - Xen disk fixes. No longer generates volumes for Xen disks, but the
  corresponding file or block disk. (bsc#1175987)

  - Invalidate file list cache when cache file modified time is in the
  future. (bsc#1176397)

  - Prevent import errors when running test_btrfs unit tests.

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1833=1" );
	script_tag( name: "affected", value: "'salt' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "python2-salt", rpm: "python2-salt~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-salt", rpm: "python3-salt~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt", rpm: "salt~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-api", rpm: "salt-api~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-cloud", rpm: "salt-cloud~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-doc", rpm: "salt-doc~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-master", rpm: "salt-master~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-minion", rpm: "salt-minion~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-proxy", rpm: "salt-proxy~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-ssh", rpm: "salt-ssh~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-standalone-formulas-configuration", rpm: "salt-standalone-formulas-configuration~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-syndic", rpm: "salt-syndic~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-bash-completion", rpm: "salt-bash-completion~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-fish-completion", rpm: "salt-fish-completion~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-zsh-completion", rpm: "salt-zsh-completion~3000~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
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

