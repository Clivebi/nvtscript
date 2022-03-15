if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852923" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2019-14857" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-30 00:15:00 +0000 (Thu, 30 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:46:07 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for apache2-mod_auth_openidc (openSUSE-SU-2019:2499-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2499-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00030.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2-mod_auth_openidc'
  package(s) announced via the openSUSE-SU-2019:2499-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for apache2-mod_auth_openidc fixes the following issues:

  - CVE-2019-14857: Fixed an open redirect issue that exists in URLs with
  trailing slashes (bsc#1153666).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2499=1" );
	script_tag( name: "affected", value: "'apache2-mod_auth_openidc' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_auth_openidc", rpm: "apache2-mod_auth_openidc~2.3.8~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_auth_openidc-debuginfo", rpm: "apache2-mod_auth_openidc-debuginfo~2.3.8~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_auth_openidc-debugsource", rpm: "apache2-mod_auth_openidc-debugsource~2.3.8~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
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

