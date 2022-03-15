if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851911" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-26 08:20:30 +0200 (Wed, 26 Sep 2018)" );
	script_cve_id( "CVE-2018-16381" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-29 20:17:00 +0000 (Mon, 29 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for php5-smarty3 (openSUSE-SU-2018:2859-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php5-smarty3'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for php5-smarty3 fixes the following issues:

  - CVE-2018-16381: Prevent traversal vulnerability due to insufficient
  template code sanitization that allowed attackers controlling the
  executed template code to bypass the trusted directory security
  restriction and read arbitrary files (bsc#1108741).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1052=1" );
	script_tag( name: "affected", value: "php5-smarty3 on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2859-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00077.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "php5-smarty3", rpm: "php5-smarty3~3.1.33~5.5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-smarty3-doc", rpm: "php5-smarty3-doc~3.1.33~5.5.1", rls: "openSUSELeap42.3" ) )){
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

