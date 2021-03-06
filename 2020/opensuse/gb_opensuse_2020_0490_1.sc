if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853103" );
	script_version( "2020-04-21T09:23:28+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-21 09:23:28 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-10 03:00:38 +0000 (Fri, 10 Apr 2020)" );
	script_name( "openSUSE: Security Advisory for gnuhealth (openSUSE-SU-2020:0490-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0490-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00011.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnuhealth'
  package(s) announced via the openSUSE-SU-2020:0490-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gnuhealth fixes the following issues:

  - Fixed a local privilege escalation in gnuhealth-control, use of static
  tmp file/http transport (bsc#1167126)

  - Fixed a local DoS of backup functionality in gnuhealth-control due to
  use of static tmp files (bsc#1167128)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-490=1" );
	script_tag( name: "affected", value: "'gnuhealth' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "gnuhealth", rpm: "gnuhealth~3.4.1~lp151.2.11.1", rls: "openSUSELeap15.1" ) )){
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

