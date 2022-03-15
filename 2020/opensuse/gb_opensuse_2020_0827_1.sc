if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853217" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2017-9103", "CVE-2017-9104", "CVE-2017-9105", "CVE-2017-9106", "CVE-2017-9107", "CVE-2017-9108", "CVE-2017-9109" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-02 03:15:00 +0000 (Thu, 02 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-06-18 03:01:09 +0000 (Thu, 18 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for adns (openSUSE-SU-2020:0827-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0827-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00037.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'adns'
  package(s) announced via the openSUSE-SU-2020:0827-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for adns fixes the following issues:

  - CVE-2017-9103, CVE-2017-9104, CVE-2017-9105, CVE-2017-9109: Fixed an issue
  in local recursive resolver which could have led to remote code
  execution (bsc#1172265).

  - CVE-2017-9106: Fixed an issue with upstream DNS data sources which could
  have led to denial of service (bsc#1172265).

  - CVE-2017-9107: Fixed an issue when querying domain names which could have
  led to denial of service (bsc#1172265).

  - CVE-2017-9108: Fixed an issue which could have led to denial of service
  (bsc#1172265).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-827=1" );
	script_tag( name: "affected", value: "'adns' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "adns", rpm: "adns~1.5.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "adns-debuginfo", rpm: "adns-debuginfo~1.5.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "adns-debugsource", rpm: "adns-debugsource~1.5.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libadns-devel", rpm: "libadns-devel~1.5.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libadns1", rpm: "libadns1~1.5.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libadns1-debuginfo", rpm: "libadns1-debuginfo~1.5.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libadns-devel-32bit", rpm: "libadns-devel-32bit~1.5.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libadns1-32bit", rpm: "libadns1-32bit~1.5.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libadns1-32bit-debuginfo", rpm: "libadns1-32bit-debuginfo~1.5.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
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

