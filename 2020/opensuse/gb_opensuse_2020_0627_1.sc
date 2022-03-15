if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853159" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2020-5267" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 02:15:00 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-05-12 03:03:55 +0000 (Tue, 12 May 2020)" );
	script_name( "openSUSE: Security Advisory for rubygem-actionview-5_1 (openSUSE-SU-2020:0627-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0627-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00019.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-actionview-5_1'
  package(s) announced via the openSUSE-SU-2020:0627-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rubygem-actionview-5_1 fixes the following issues:

  - CVE-2020-5267: Fixed an XSS vulnerability in ActionView's JavaScript
  literal escape helpers (bsc#1167240).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-627=1" );
	script_tag( name: "affected", value: "'rubygem-actionview-5_1' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-rubygem-actionview-5_1", rpm: "ruby2.5-rubygem-actionview-5_1~5.1.4~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uby2.5-rubygem-actionview-doc-5_1", rpm: "uby2.5-rubygem-actionview-doc-5_1~5.1.4~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
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

