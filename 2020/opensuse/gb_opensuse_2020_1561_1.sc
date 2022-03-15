if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853464" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2019-14973" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-06 01:15:00 +0000 (Fri, 06 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-09-29 03:02:12 +0000 (Tue, 29 Sep 2020)" );
	script_name( "openSUSE: Security Advisory for tiff (openSUSE-SU-2020:1561-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1561-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00102.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tiff'
  package(s) announced via the openSUSE-SU-2020:1561-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tiff fixes the following issues:

  - CVE-2019-14973: Fixed an improper check which was depended on the
  compiler which could have led to integer overflow (bsc#1146608).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1561=1" );
	script_tag( name: "affected", value: "'tiff' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libtiff-devel", rpm: "libtiff-devel~4.0.9~lp152.11.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5", rpm: "libtiff5~4.0.9~lp152.11.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-debuginfo", rpm: "libtiff5-debuginfo~4.0.9~lp152.11.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff", rpm: "tiff~4.0.9~lp152.11.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff-debuginfo", rpm: "tiff-debuginfo~4.0.9~lp152.11.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff-debugsource", rpm: "tiff-debugsource~4.0.9~lp152.11.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff-devel-32bit", rpm: "libtiff-devel-32bit~4.0.9~lp152.11.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-32bit", rpm: "libtiff5-32bit~4.0.9~lp152.11.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-32bit-debuginfo", rpm: "libtiff5-32bit-debuginfo~4.0.9~lp152.11.3.1", rls: "openSUSELeap15.2" ) )){
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

