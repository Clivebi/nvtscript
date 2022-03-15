if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853715" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2020-14352" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-09 14:28:00 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:01:21 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for librepo (openSUSE-SU-2021:0277-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0277-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GMUBDUMWN7YJEDAXCHHKHS3ODSQ7RUOF" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'librepo'
  package(s) announced via the openSUSE-SU-2021:0277-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for librepo fixes the following issues:

  - Upgrade to 1.12.1
       + Validate path read from repomd.xml (bsc#1175475, CVE-2020-14352)

  - Changes from 1.12.0
       + Prefer mirrorlist/metalink over baseurl (rh#1775184)
       + Decode package URL when using for local filename (rh#1817130)
       + Fix memory leak in lr_download_metadata() and lr_yum_download_remote()
       + Download sources work when at least one of specified is working
         (rh#1775184)

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'librepo' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "librepo-debuginfo", rpm: "librepo-debuginfo~1.12.1~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librepo-debugsource", rpm: "librepo-debugsource~1.12.1~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librepo-devel", rpm: "librepo-devel~1.12.1~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librepo0", rpm: "librepo0~1.12.1~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librepo0-debuginfo", rpm: "librepo0-debuginfo~1.12.1~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-librepo", rpm: "python3-librepo~1.12.1~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-librepo-debuginfo", rpm: "python3-librepo-debuginfo~1.12.1~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
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

