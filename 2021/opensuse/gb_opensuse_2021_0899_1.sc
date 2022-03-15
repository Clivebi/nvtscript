if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853874" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2018-15750", "CVE-2018-15751", "CVE-2020-11651", "CVE-2020-11652", "CVE-2020-25592", "CVE-2021-25315", "CVE-2021-31607" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-20 01:17:00 +0000 (Thu, 20 Aug 2020)" );
	script_tag( name: "creation_date", value: "2021-06-24 03:02:05 +0000 (Thu, 24 Jun 2021)" );
	script_name( "openSUSE: Security Advisory for salt (openSUSE-SU-2021:0899-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0899-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6E3YAO2VV3WBUS7PMAT26ZYDS3AXW5VL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'salt'
  package(s) announced via the openSUSE-SU-2021:0899-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for salt fixes the following issues:

     Update to Salt release version 3002.2 (jsc#ECO-3212, jsc#SLE-18033,
     jsc#SLE-18028)

  - Check if dpkgnotify is executable (bsc#1186674)

  - Drop support for Python2. Obsoletes `python2-salt` package
       (jsc#SLE-18028)

  - virt module updates

  * network: handle missing ipv4 netmask attribute

  * more network support

  * PCI/USB host devices passthrough support

  - Set distro requirement to oldest supported version in
       requirements/base.txt

  - Bring missing part of async batch implementation back (CVE-2021-25315,
       bsc#1182382)

  - Always require `python3-distro` (bsc#1182293)

  - Remove deprecated warning that breaks minion execution when
       'server_id_use_crc' opts is missing

  - Fix pkg states when DEB package has 'all' arch

  - Do not force beacons configuration to be a list.

  - Remove msgpack   1.0.0 from base requirements (bsc#1176293)

  - msgpack support for version  = 1.0.0 (bsc#1171257)

  - Fix issue parsing errors in ansiblegate state module

  - Prevent command injection in the snapper module (bsc#1185281,
       CVE-2021-31607)

  - transactional_update: detect recursion in the executor

  - Add subpackage salt-transactional-update (jsc#SLE-18033)

  - Improvements on 'ansiblegate' module (bsc#1185092):

  * New methods: ansible.targets / ansible.discover_playbooks

  - Add support for Alibaba Cloud Linux 2 (Aliyun Linux)

  - Regression fix of salt-ssh on processing targets

  - Update target fix for salt-ssh and avoiding race condition on salt-ssh
       event processing (bsc#1179831, bsc#1182281)

  - Add notify beacon for Debian/Ubuntu systems

  - Fix zmq bug that causes salt-call to freeze (bsc#1181368)

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
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
	if(!isnull( res = isrpmvuln( pkg: "python3-salt", rpm: "python3-salt~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt", rpm: "salt~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-api", rpm: "salt-api~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-cloud", rpm: "salt-cloud~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-doc", rpm: "salt-doc~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-master", rpm: "salt-master~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-minion", rpm: "salt-minion~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-proxy", rpm: "salt-proxy~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-ssh", rpm: "salt-ssh~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-standalone-formulas-configuration", rpm: "salt-standalone-formulas-configuration~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-syndic", rpm: "salt-syndic~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-transactional-update", rpm: "salt-transactional-update~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-bash-completion", rpm: "salt-bash-completion~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-fish-completion", rpm: "salt-fish-completion~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-zsh-completion", rpm: "salt-zsh-completion~3002.2~lp152.3.36.1", rls: "openSUSELeap15.2" ) )){
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

