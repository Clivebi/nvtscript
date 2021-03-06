if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852768" );
	script_version( "2020-01-31T08:04:39+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-11-11 03:00:48 +0000 (Mon, 11 Nov 2019)" );
	script_name( "openSUSE: Security Advisory for Recommended (openSUSE-SU-2019:2477-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2477-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00025.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Recommended'
  package(s) announced via the openSUSE-SU-2019:2477-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for bcm20702a1-firmware fixes the following issues:

  Changes in bcm20702a1-firmware:

  - Use https to fetch the archive to avoid person-in-the-middle attacks
  (boo#1154083)

  - Fetch & install another variant firmware (0a5c:21e8) (boo#1087996)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2477=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2477=1" );
	script_tag( name: "affected", value: "'Recommended' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "cm20702a1-firmware", rpm: "cm20702a1-firmware~1201650~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

