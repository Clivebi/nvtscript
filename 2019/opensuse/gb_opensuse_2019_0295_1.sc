if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852335" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2019-5736" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-01 20:15:00 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-03-07 04:12:22 +0100 (Thu, 07 Mar 2019)" );
	script_name( "openSUSE: Security Advisory for containerd (openSUSE-SU-2019:0295-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0295-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-03/msg00008.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'containerd'
  package(s) announced via the openSUSE-SU-2019:0295-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for containerd, docker, docker-runc,
  golang-github-docker-libnetwork, runc fixes the following issues:

  Security issues fixed:

  - CVE-2018-16875: Fixed a CPU Denial of Service (bsc#1118899).

  - CVE-2018-16874: Fixed a vulnerabity in go get command which could allow
  directory traversal in GOPATH mode (bsc#1118898).

  - CVE-2018-16873: Fixed a vulnerability in go get command which could
  allow remote code execution when executed with -u in GOPATH mode
  (bsc#1118897).

  - CVE-2019-5736: Effectively copying /proc/self/exe during re-exec to
  avoid write attacks to the host runc binary, which could lead to a
  container breakout (bsc#1121967).

  Other changes and fixes:

  - Update shell completion to use Group: System/Shells.

  - Add daemon.json file with rotation logs configuration (bsc#1114832)

  - Update to Docker 18.09.1-ce (bsc#1124308) and to runc 96ec2177ae84.
  See upstream changelog in the packaged
  /usr/share/doc/packages/docker/CHANGELOG.md.

  - Update go requirements to  = go1.10

  - Use -buildmode=pie for tests and binary build (bsc#1048046 and
  bsc#1051429).

  - Remove the usage of 'cp -r' to reduce noise in the build logs.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-295=1" );
	script_tag( name: "affected", value: "containerd, on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "containerd-test", rpm: "containerd-test~1.2.2~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-bash-completion", rpm: "docker-bash-completion~18.09.1_ce~lp150.5.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc-test", rpm: "docker-runc-test~1.0.0rc6+gitr3748_96ec2177ae84~lp150.5.14.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-zsh-completion", rpm: "docker-zsh-completion~18.09.1_ce~lp150.5.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "runc-test", rpm: "runc-test~1.0.0~rc6~lp150.2.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "containerd", rpm: "containerd~1.2.2~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "containerd-ctr", rpm: "containerd-ctr~1.2.2~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker", rpm: "docker~18.09.1_ce~lp150.5.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-debuginfo", rpm: "docker-debuginfo~18.09.1_ce~lp150.5.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-debugsource", rpm: "docker-debugsource~18.09.1_ce~lp150.5.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-libnetwork", rpm: "docker-libnetwork~0.7.0.1+gitr2711_2cfbf9b1f981~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-libnetwork-debuginfo", rpm: "docker-libnetwork-debuginfo~0.7.0.1+gitr2711_2cfbf9b1f981~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc", rpm: "docker-runc~1.0.0rc6+gitr3748_96ec2177ae84~lp150.5.14.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc-debuginfo", rpm: "docker-runc-debuginfo~1.0.0rc6+gitr3748_96ec2177ae84~lp150.5.14.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-test", rpm: "docker-test~18.09.1_ce~lp150.5.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-test-debuginfo", rpm: "docker-test-debuginfo~18.09.1_ce~lp150.5.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-github-docker-libnetwork", rpm: "golang-github-docker-libnetwork~0.7.0.1+gitr2711_2cfbf9b1f981~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "runc", rpm: "runc~1.0.0~rc6~lp150.2.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unc-debuginfo", rpm: "unc-debuginfo~1.0.0~rc6~lp150.2.7.1", rls: "openSUSELeap15.0" ) )){
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

