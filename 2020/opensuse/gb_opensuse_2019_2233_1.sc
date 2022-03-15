if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852827" );
	script_version( "2021-08-13T03:00:58+0000" );
	script_cve_id( "CVE-2019-13104", "CVE-2019-13106" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-08-13 03:00:58 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-01 18:15:00 +0000 (Tue, 01 Oct 2019)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:33:40 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for u-boot (openSUSE-SU-2019:2233-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2233-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-10/msg00002.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'u-boot'
  package(s) announced via the openSUSE-SU-2019:2233-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for u-boot fixes the following issues:

  Security issues fixed:

  - CVE-2019-13106: Fixed stack buffer overflow via a crafted ext4
  filesystem that may lead to code execution (bsc#1144656).

  - CVE-2019-13104: Fixed an underflow that could cause memcpy() to
  overwrite a very large amount of data via a crafted ext4 filesystem
  (bsc#1144675).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2233=1" );
	script_tag( name: "affected", value: "'u-boot' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "u-boot-tools", rpm: "u-boot-tools~2019.01~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "u-boot-tools-debuginfo", rpm: "u-boot-tools-debuginfo~2019.01~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
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

