if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852467" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2016-9396", "CVE-2018-19539", "CVE-2018-19542" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-03 04:15:00 +0000 (Wed, 03 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-05-03 02:00:41 +0000 (Fri, 03 May 2019)" );
	script_name( "openSUSE: Security Advisory for jasper (openSUSE-SU-2019:1315-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1315-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00004.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jasper'
  package(s) announced via the openSUSE-SU-2019:1315-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for jasper fixes the following issues:

  Security issues fixed:

  - CVE-2018-19542: Fixed a denial of service in jp2_decode (bsc#1117505).

  - CVE-2018-19539: Fixed a denial of service in jas_image_readcmpt
  (bsc#1117511).

  - CVE-2016-9396: Fixed a denial of service in jpc_cox_getcompparms
  (bsc#1010783).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1315=1" );
	script_tag( name: "affected", value: "'jasper' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "jasper", rpm: "jasper~2.0.14~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jasper-debuginfo", rpm: "jasper-debuginfo~2.0.14~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jasper-debugsource", rpm: "jasper-debugsource~2.0.14~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper-devel", rpm: "libjasper-devel~2.0.14~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper4", rpm: "libjasper4~2.0.14~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper4-debuginfo", rpm: "libjasper4-debuginfo~2.0.14~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper4-32bit", rpm: "libjasper4-32bit~2.0.14~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper4-32bit-debuginfo", rpm: "libjasper4-32bit-debuginfo~2.0.14~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

