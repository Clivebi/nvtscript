if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852294" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-03 18:29:00 +0000 (Mon, 03 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-02-17 04:04:42 +0100 (Sun, 17 Feb 2019)" );
	script_name( "openSUSE: Security Advisory for docker (openSUSE-SU-2019:0189-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0189-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00030.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'docker'
  package(s) announced via the openSUSE-SU-2019:0189-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for containerd, docker, docker-runc and
  golang-github-docker-libnetwork fixes the following issues:

  Security issues fixed for containerd, docker, docker-runc and
  golang-github-docker-libnetwork:

  - CVE-2018-16873: cmd/go: remote command execution during 'go get -u'
  (bsc#1118897)

  - CVE-2018-16874: cmd/go: directory traversal in 'go get' via curly braces
  in import paths (bsc#1118898)

  - CVE-2018-16875: crypto/x509: CPU denial of service (bsc#1118899)

  Non-security issues fixed for docker:

  - Disable leap based builds for kubic flavor (bsc#1121412)

  - Allow users to explicitly specify the NIS domainname of a container
  (bsc#1001161)

  - Update docker.service to match upstream and avoid rlimit problems
  (bsc#1112980)

  - Allow docker images larger then 23GB (bsc#1118990)

  - Docker version update to version 18.09.0-ce (bsc#1115464)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-189=1" );
	script_tag( name: "affected", value: "docker on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "containerd-test", rpm: "containerd-test~1.1.2~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-bash-completion", rpm: "docker-bash-completion~18.09.0_ce~lp150.5.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc-test", rpm: "docker-runc-test~1.0.0rc5+gitr3562_69663f0bd4b6~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-zsh-completion", rpm: "docker-zsh-completion~18.09.0_ce~lp150.5.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "containerd", rpm: "containerd~1.1.2~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "containerd-ctr", rpm: "containerd-ctr~1.1.2~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker", rpm: "docker~18.09.0_ce~lp150.5.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-debuginfo", rpm: "docker-debuginfo~18.09.0_ce~lp150.5.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-debugsource", rpm: "docker-debugsource~18.09.0_ce~lp150.5.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-libnetwork", rpm: "docker-libnetwork~0.7.0.1+gitr2704_6da50d197830~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-libnetwork-debuginfo", rpm: "docker-libnetwork-debuginfo~0.7.0.1+gitr2704_6da50d197830~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc", rpm: "docker-runc~1.0.0rc5+gitr3562_69663f0bd4b6~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc-debuginfo", rpm: "docker-runc-debuginfo~1.0.0rc5+gitr3562_69663f0bd4b6~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-test", rpm: "docker-test~18.09.0_ce~lp150.5.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-test-debuginfo", rpm: "docker-test-debuginfo~18.09.0_ce~lp150.5.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-github-docker-libnetwork", rpm: "golang-github-docker-libnetwork~0.7.0.1+gitr2704_6da50d197830~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
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

