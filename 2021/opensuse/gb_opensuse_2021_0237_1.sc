if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853721" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2019-5477", "CVE-2020-26247" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-16 14:48:00 +0000 (Fri, 16 Oct 2020)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:01:36 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for rubygem-nokogiri (openSUSE-SU-2021:0237-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0237-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RLEJCRYIVSTKE34ZJIXITKLZOOKOAMWQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-nokogiri'
  package(s) announced via the openSUSE-SU-2021:0237-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rubygem-nokogiri fixes the following issues:

     rubygem-nokogiri was updated to 1.8.5 (bsc#1156722).

     Security issues fixed:

  - CVE-2019-5477: Fixed a command injection vulnerability (bsc#1146578).

  - CVE-2020-26247: Fixed an XXE vulnerability in Nokogiri::XML::Schema
       (bsc#1180507).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'rubygem-nokogiri' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-rubygem-nokogiri", rpm: "ruby2.5-rubygem-nokogiri~1.8.5~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-rubygem-nokogiri-debuginfo", rpm: "ruby2.5-rubygem-nokogiri-debuginfo~1.8.5~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-rubygem-nokogiri-doc", rpm: "ruby2.5-rubygem-nokogiri-doc~1.8.5~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-rubygem-nokogiri-testsuite", rpm: "ruby2.5-rubygem-nokogiri-testsuite~1.8.5~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-nokogiri-debugsource", rpm: "rubygem-nokogiri-debugsource~1.8.5~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
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

