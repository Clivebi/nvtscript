if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853622" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2019-16091", "CVE-2019-16092", "CVE-2019-16093", "CVE-2019-16094", "CVE-2019-16095", "CVE-2019-20016", "CVE-2019-20063", "CVE-2020-36148", "CVE-2020-36149", "CVE-2020-36150", "CVE-2020-36151", "CVE-2020-36152", "CVE-2020-6860" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-01 16:15:00 +0000 (Tue, 01 Sep 2020)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:57:06 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for libmysofa (openSUSE-SU-2021:0444-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0444-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UFAOL5LVMXJXRBU3JU2LMHQNMBUBR7BH" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmysofa'
  package(s) announced via the openSUSE-SU-2021:0444-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libmysofa fixes the following issues:

  - Added security backports: gh#hoene/libmysofa#136 - CVE-2020-36152 -
       boo#1181977 gh#hoene/libmysofa#138 - CVE-2020-36148 - boo#1181981
       gh#hoene/libmysofa#137 - CVE-2020-36149 - boo#1181980
       gh#hoene/libmysofa#134 - CVE-2020-36151 - boo#1181978
       gh#hoene/libmysofa#135 - CVE-2020-36150 - boo#1181979
       gh#hoene/libmysofa#96 - CVE-2020-6860 - boo#1182883

     Update to version 0.9.1

  * Extended angular neighbor search to &#x27 close the sphere&#x27

  * Added and exposed mysofa_getfilter_float_nointerp method

  * Fixed various security issues CVE-2019-16091 - boo#1149919
         CVE-2019-16092 - boo#1149920 CVE-2019-16093 - boo#1149922
         CVE-2019-16094 - boo#1149924 CVE-2019-16095 - boo#1149926
         CVE-2019-20016 - boo#1159839 CVE-2019-20063 - boo#1160040" );
	script_tag( name: "affected", value: "'libmysofa' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libmysofa-debugsource", rpm: "libmysofa-debugsource~0.9.1~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysofa-devel", rpm: "libmysofa-devel~0.9.1~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysofa0", rpm: "libmysofa0~0.9.1~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysofa0-debuginfo", rpm: "libmysofa0-debuginfo~0.9.1~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
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

