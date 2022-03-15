if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853568" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2020-10648", "CVE-2020-8432" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 14:53:00 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-11-08 04:01:01 +0000 (Sun, 08 Nov 2020)" );
	script_name( "openSUSE: Security Advisory for u-boot (openSUSE-SU-2020:1869-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1869-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00030.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'u-boot'
  package(s) announced via the openSUSE-SU-2020:1869-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for u-boot fixes the following issues:

  - CVE-2020-8432: Fixed a double free in the cmd/gpt.c
  do_rename_gpt_parts() function, which allowed an attacker to execute
  arbitrary code (bsc#1162198)

  - CVE-2020-10648: Fixed improper signature verification during verified
  boot (bsc#1167209).

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1869=1" );
	script_tag( name: "affected", value: "'u-boot' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "u-boot-tools", rpm: "u-boot-tools~2020.01~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "u-boot-tools-debuginfo", rpm: "u-boot-tools-debuginfo~2020.01~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
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

