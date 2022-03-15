if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853323" );
	script_version( "2020-08-07T07:29:19+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-07 07:29:19 +0000 (Fri, 07 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-28 03:01:29 +0000 (Tue, 28 Jul 2020)" );
	script_name( "openSUSE: Security Advisory for perl-YAML-LibYAML (openSUSE-SU-2020:1093-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1093-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00081.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-YAML-LibYAML'
  package(s) announced via the openSUSE-SU-2020:1093-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for perl-YAML-LibYAML fixes the following issues:

  perl-YAML-LibYAML was updated to 0.69: [bsc#1173703]

  * Security fix: Add $LoadBlessed option to turn on/off loading objects:
  Default is set to true. Note that, the behavior is unchanged.

  * Clarify documentation about exported functions

  * Dump() was modifying original data, adding a PV to numbers

  * Support standard tags !!str, !!map and !!seq instead of dying.

  * Support JSON::PP::Boolean and boolean.pm via $YAML::XS::Boolean.

  * Fix regex roundtrip. Fix loading of many regexes.


  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1093=1" );
	script_tag( name: "affected", value: "'perl-YAML-LibYAML' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "perl-YAML-LibYAML", rpm: "perl-YAML-LibYAML~0.69~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-YAML-LibYAML-debuginfo", rpm: "perl-YAML-LibYAML-debuginfo~0.69~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-YAML-LibYAML-debugsource", rpm: "perl-YAML-LibYAML-debugsource~0.69~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
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

