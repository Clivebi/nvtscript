if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852050" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_cve_id( "CVE-2017-5715" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 14:52:00 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:38:03 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for kernel-firmware (openSUSE-SU-2018:2237-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:2237-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00020.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-firmware'
  package(s) announced via the openSUSE-SU-2018:2237-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for kernel-firmware to version 20180525 fixes the following
  issues:

  This security issue was fixed:

  - CVE-2017-5715: Prevent unauthorized disclosure of information to an
  attacker with local user access caused by speculative execution and
  indirect branch prediction (bsc#1095735)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-825=1" );
	script_tag( name: "affected", value: "kernel-firmware on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-firmware", rpm: "kernel-firmware~20180525~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ucode-amd", rpm: "ucode-amd~20180525~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

