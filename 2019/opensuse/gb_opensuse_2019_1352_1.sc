if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852484" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2019-0161" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-29 22:15:00 +0000 (Thu, 29 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-05-09 02:01:00 +0000 (Thu, 09 May 2019)" );
	script_name( "openSUSE: Security Advisory for ovmf (openSUSE-SU-2019:1352-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1352-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00019.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ovmf'
  package(s) announced via the openSUSE-SU-2019:1352-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ovmf fixes the following issues:

  Security issue fixed:

  - CVE-2019-0161: Fixed a stack overflow in UsbBusDxe and UsbBusPei, which
  could potentially be triggered by a local unauthenticated user
  (bsc#1131361).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1352=1" );
	script_tag( name: "affected", value: "'ovmf' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "ovmf", rpm: "ovmf~2017+git1510945757.b2662641d5~lp150.4.19.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ovmf-tools", rpm: "ovmf-tools~2017+git1510945757.b2662641d5~lp150.4.19.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ovmf-ia32", rpm: "qemu-ovmf-ia32~2017+git1510945757.b2662641d5~lp150.4.19.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ovmf-x86-64", rpm: "qemu-ovmf-x86-64~2017+git1510945757.b2662641d5~lp150.4.19.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ovmf-x86-64-debug", rpm: "qemu-ovmf-x86-64-debug~2017+git1510945757.b2662641d5~lp150.4.19.1", rls: "openSUSELeap15.0" ) )){
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

