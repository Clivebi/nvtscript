if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853733" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2020-25613" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-15 11:15:00 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:02:19 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for ruby2.5 (openSUSE-SU-2021:0471-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0471-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RPFN4SV4JCJUNCQC4PQZ6VEJN63VN2FS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby2.5'
  package(s) announced via the openSUSE-SU-2021:0471-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ruby2.5 fixes the following issues:

  - CVE-2020-25613: Fixed a potential HTTP Request Smuggling  in WEBrick
       (bsc#1177125).

  - Enable optimizations also on ARM64 (bsc#1177222)

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'ruby2.5' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libruby2_5-2_5", rpm: "libruby2_5-2_5~2.5.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libruby2_5-2_5-debuginfo", rpm: "libruby2_5-2_5-debuginfo~2.5.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5", rpm: "ruby2.5~2.5.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-debuginfo", rpm: "ruby2.5-debuginfo~2.5.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-debugsource", rpm: "ruby2.5-debugsource~2.5.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-devel", rpm: "ruby2.5-devel~2.5.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-devel-extra", rpm: "ruby2.5-devel-extra~2.5.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-doc", rpm: "ruby2.5-doc~2.5.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-stdlib", rpm: "ruby2.5-stdlib~2.5.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-stdlib-debuginfo", rpm: "ruby2.5-stdlib-debuginfo~2.5.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-doc-ri", rpm: "ruby2.5-doc-ri~2.5.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

