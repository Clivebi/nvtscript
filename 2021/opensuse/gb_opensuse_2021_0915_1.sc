if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853883" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2019-15232", "CVE-2021-28899" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-15 00:15:00 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "creation_date", value: "2021-06-25 03:01:48 +0000 (Fri, 25 Jun 2021)" );
	script_name( "openSUSE: Security Advisory for live555 (openSUSE-SU-2021:0915-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0915-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Y7ZOGH7UAC6Q7OJHR62KOMWS64YF4G73" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'live555'
  package(s) announced via the openSUSE-SU-2021:0915-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for live555 fixes the following issues:

     Update to 2021.05.22:

  - Lots of fixes and updates, including the security fix for CVE-2021-28899" );
	script_tag( name: "affected", value: "'live555' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libBasicUsageEnvironment1", rpm: "libBasicUsageEnvironment1~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libBasicUsageEnvironment1-debuginfo", rpm: "libBasicUsageEnvironment1-debuginfo~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libUsageEnvironment3", rpm: "libUsageEnvironment3~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libUsageEnvironment3-debuginfo", rpm: "libUsageEnvironment3-debuginfo~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgroupsock30", rpm: "libgroupsock30~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgroupsock30-debuginfo", rpm: "libgroupsock30-debuginfo~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libliveMedia94", rpm: "libliveMedia94~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libliveMedia94-debuginfo", rpm: "libliveMedia94-debuginfo~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "live555", rpm: "live555~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "live555-debuginfo", rpm: "live555-debuginfo~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "live555-debugsource", rpm: "live555-debugsource~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "live555-devel", rpm: "live555-devel~2021.05.22~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
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

