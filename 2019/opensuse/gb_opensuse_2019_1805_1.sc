if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852638" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-11 16:29:00 +0000 (Tue, 11 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-07-25 02:01:52 +0000 (Thu, 25 Jul 2019)" );
	script_name( "openSUSE: Security Advisory for ucode-intel (openSUSE-SU-2019:1805-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1805-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-07/msg00053.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ucode-intel'
  package(s) announced via the openSUSE-SU-2019:1805-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ucode-intel fixes the following issues:

  This update contains the Intel QSR 2019.1 Microcode release (bsc#1111331)

  Four new speculative execution information leak issues have been
  identified in Intel CPUs. (bsc#1111331)

  - CVE-2018-12126: Microarchitectural Store Buffer Data Sampling (MSBDS)

  - CVE-2018-12127: Microarchitectural Fill Buffer Data Sampling (MFBDS)

  - CVE-2018-12130: Microarchitectural Load Port Data Samling (MLPDS)

  - CVE-2019-11091: Microarchitectural Data Sampling Uncacheable Memory
  (MDSUM)

  These updates contain the CPU Microcode adjustments for the software
  mitigations.

  Release notes:

  - --- updated platforms ------------------------------------ SNB-E/EN/EP
  C1/M0    6-2d-6/6d 0000061d->0000061f Xeon E3/E5, Core X SNB-E/EN/EP
  C2/M1    6-2d-7/6d 00000714->00000718 Xeon E3/E5, Core X

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1805=1" );
	script_tag( name: "affected", value: "'ucode-intel' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "ucode-intel", rpm: "ucode-intel~20190618~lp150.2.24.1", rls: "openSUSELeap15.0" ) )){
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

