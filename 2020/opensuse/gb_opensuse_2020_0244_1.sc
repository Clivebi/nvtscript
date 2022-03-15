if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853044" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2019-18634" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-07 17:15:00 +0000 (Fri, 07 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-02-26 04:00:31 +0000 (Wed, 26 Feb 2020)" );
	script_name( "openSUSE: Security Advisory for sudo (openSUSE-SU-2020:0244-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0244-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00029.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sudo'
  package(s) announced via the openSUSE-SU-2020:0244-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for sudo fixes the following issues:

  Security issue fixed:

  - CVE-2019-18634: Fixed a buffer overflow in the passphrase prompt that
  could occur when pwfeedback was enabled in /etc/sudoers (bsc#1162202).

  Non-security issue fixed:

  - Fixed an issue where sudo -l would ask for a password even though
  `listpw` was set to `never` (bsc#1162675).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-244=1" );
	script_tag( name: "affected", value: "'sudo' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "sudo", rpm: "sudo~1.8.22~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sudo-debuginfo", rpm: "sudo-debuginfo~1.8.22~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sudo-debugsource", rpm: "sudo-debugsource~1.8.22~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sudo-devel", rpm: "sudo-devel~1.8.22~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sudo-test", rpm: "sudo-test~1.8.22~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
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

