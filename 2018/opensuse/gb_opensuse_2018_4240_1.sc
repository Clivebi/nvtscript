if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852208" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_cve_id( "CVE-2017-5731", "CVE-2017-5732", "CVE-2017-5733", "CVE-2017-5734", "CVE-2017-5735", "CVE-2018-3613" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-18 17:38:00 +0000 (Mon, 18 Nov 2019)" );
	script_tag( name: "creation_date", value: "2018-12-23 04:01:25 +0100 (Sun, 23 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for ovmf (openSUSE-SU-2018:4240-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:4240-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00055.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ovmf'
  package(s) announced via the openSUSE-SU-2018:4240-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ovmf fixes the following issues:

  Security issues fixed:

  - CVE-2018-3613: Fixed AuthVariable Timestamp zeroing issue on
  APPEND_WRITE (bsc#1115916).

  - CVE-2017-5731: Fixed privilege escalation via processing of malformed
  files in TianoCompress.c (bsc#1115917).

  - CVE-2017-5732: Fixed privilege escalation via processing of malformed
  files in BaseUefiDecompressLib.c (bsc#1115917).

  - CVE-2017-5733: Fixed privilege escalation via heap-based buffer overflow
  in MakeTable() function (bsc#1115917).

  - CVE-2017-5734: Fixed privilege escalation via stack-based buffer
  overflow in MakeTable() function (bsc#1115917).

  - CVE-2017-5735: Fixed privilege escalation via heap-based buffer overflow
  in Decode() function (bsc#1115917).

  Non security issues fixed:

  - Fixed an issue with the default owner of PK/KEK/db/dbx and make the
  auto-enrollment only happen at the very first time. (bsc#1117998)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1590=1" );
	script_tag( name: "affected", value: "ovmf on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "ovmf", rpm: "ovmf~2017+git1510945757.b2662641d5~lp150.4.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ovmf-tools", rpm: "ovmf-tools~2017+git1510945757.b2662641d5~lp150.4.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ovmf-x86-64-debug", rpm: "qemu-ovmf-x86-64-debug~2017+git1510945757.b2662641d5~lp150.4.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ovmf-ia32", rpm: "qemu-ovmf-ia32~2017+git1510945757.b2662641d5~lp150.4.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ovmf-x86-64", rpm: "qemu-ovmf-x86-64~2017+git1510945757.b2662641d5~lp150.4.9.1", rls: "openSUSELeap15.0" ) )){
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

