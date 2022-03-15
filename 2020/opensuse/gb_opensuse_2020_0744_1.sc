if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853189" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2019-18898" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-20 16:15:00 +0000 (Fri, 20 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-05-30 03:00:38 +0000 (Sat, 30 May 2020)" );
	script_name( "openSUSE: Security Advisory for trousers (openSUSE-SU-2020:0744-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0744-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00066.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'trousers'
  package(s) announced via the openSUSE-SU-2020:0744-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for trousers fixes the following issues:

  - CVE-2019-18898: Fixed a local symlink attack where a rogue tss user
  could have gain ownership of arbitrary files in the system during
  installation/update of the trousers package (bsc#1157651).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-744=1" );
	script_tag( name: "affected", value: "'trousers' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libtspi1", rpm: "libtspi1~0.3.14~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtspi1-debuginfo", rpm: "libtspi1-debuginfo~0.3.14~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "trousers", rpm: "trousers~0.3.14~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "trousers-debuginfo", rpm: "trousers-debuginfo~0.3.14~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "trousers-debugsource", rpm: "trousers-debugsource~0.3.14~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "trousers-devel", rpm: "trousers-devel~0.3.14~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtspi1-32bit", rpm: "libtspi1-32bit~0.3.14~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtspi1-32bit-debuginfo", rpm: "libtspi1-32bit-debuginfo~0.3.14~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
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

