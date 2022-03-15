if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853271" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2020-15304", "CVE-2020-15305", "CVE-2020-15306" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-11 04:15:00 +0000 (Sun, 11 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-17 03:01:49 +0000 (Fri, 17 Jul 2020)" );
	script_name( "openSUSE: Security Advisory for openexr (openSUSE-SU-2020:0970-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0970-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00025.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openexr'
  package(s) announced via the openSUSE-SU-2020:0970-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openexr fixes the following issues:

  - CVE-2020-15304: Fixed a NULL pointer dereference in
  TiledInputFile:TiledInputFile() (bsc#1173466).

  - CVE-2020-15305: Fixed a use-after-free in
  DeepScanLineInputFile:DeepScanLineInputFile() (bsc#1173467).

  - CVE-2020-15306: Fixed a heap buffer overflow in
  getChunkOffsetTableSize() (bsc#1173469).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-970=1" );
	script_tag( name: "affected", value: "'openexr' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23", rpm: "libIlmImf-2_2-23~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23-debuginfo", rpm: "libIlmImf-2_2-23-debuginfo~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23", rpm: "libIlmImfUtil-2_2-23~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23-debuginfo", rpm: "libIlmImfUtil-2_2-23-debuginfo~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr", rpm: "openexr~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debuginfo", rpm: "openexr-debuginfo~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debugsource", rpm: "openexr-debugsource~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-devel", rpm: "openexr-devel~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-doc", rpm: "openexr-doc~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23-32bit", rpm: "libIlmImf-2_2-23-32bit~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23-32bit-debuginfo", rpm: "libIlmImf-2_2-23-32bit-debuginfo~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23-32bit", rpm: "libIlmImfUtil-2_2-23-32bit~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23-32bit-debuginfo", rpm: "libIlmImfUtil-2_2-23-32bit-debuginfo~2.2.1~lp151.4.12.1", rls: "openSUSELeap15.1" ) )){
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

