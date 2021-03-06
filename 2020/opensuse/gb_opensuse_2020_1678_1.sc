if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853502" );
	script_version( "2020-10-22T07:09:04+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-22 07:09:04 +0000 (Thu, 22 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-18 03:00:53 +0000 (Sun, 18 Oct 2020)" );
	script_name( "openSUSE: Security Advisory for crmsh (openSUSE-SU-2020:1678-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1678-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00032.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'crmsh'
  package(s) announced via the openSUSE-SU-2020:1678-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for crmsh fixes the following issues:

  - Fixed start_delay with start-delay(bsc#1176569)

  - fix on_fail should be on-fail(bsc#1176569)

  - config: Try to handle configparser.MissingSectionHeaderError while
  reading config file

  - ui_configure: Obscure sensitive data by default(bsc#1163581)

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1678=1" );
	script_tag( name: "affected", value: "'crmsh' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "crmsh", rpm: "crmsh~4.2.0+git.1602225426.5f84efb5~lp152.4.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "crmsh-scripts", rpm: "crmsh-scripts~4.2.0+git.1602225426.5f84efb5~lp152.4.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "crmsh-test", rpm: "crmsh-test~4.2.0+git.1602225426.5f84efb5~lp152.4.27.1", rls: "openSUSELeap15.2" ) )){
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

