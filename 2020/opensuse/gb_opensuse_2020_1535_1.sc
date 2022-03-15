if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853458" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2019-14562" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-29 22:15:00 +0000 (Thu, 29 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-09-27 03:01:08 +0000 (Sun, 27 Sep 2020)" );
	script_name( "openSUSE: Security Advisory for ovmf (openSUSE-SU-2020:1535-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:1535-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00091.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ovmf'
  package(s) announced via the openSUSE-SU-2020:1535-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ovmf fixes the following issues:

  - CVE-2019-14562: Fixed an overflow in DxeImageVerificationHandler
  (bsc#1175476).

  - Use openSUSE CA for the opensuse flavor (bsc#1175674)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1535=1" );
	script_tag( name: "affected", value: "'ovmf' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "ovmf-tools-2017-git1510945757.b2662641d5", rpm: "ovmf-tools-2017-git1510945757.b2662641d5~lp151.11.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ovmf-ia32-2017-git1510945757.b2662641d5", rpm: "qemu-ovmf-ia32-2017-git1510945757.b2662641d5~lp151.11.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ovmf-x86-64-2017-git1510945757.b2662641d5", rpm: "qemu-ovmf-x86-64-2017-git1510945757.b2662641d5~lp151.11.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ovmf-x86-64-debug-2017-git1510945757.b2662641d5", rpm: "qemu-ovmf-x86-64-debug-2017-git1510945757.b2662641d5~lp151.11.9.1", rls: "openSUSELeap15.1" ) )){
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

