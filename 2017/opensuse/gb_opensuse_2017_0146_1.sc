if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851474" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-17 05:48:02 +0100 (Tue, 17 Jan 2017)" );
	script_cve_id( "CVE-2015-8010", "CVE-2016-9566" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-25 11:29:00 +0000 (Tue, 25 Dec 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for icinga (openSUSE-SU-2017:0146-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icinga'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for icinga includes various upstream fixes and the following
  security security fixes:

  - icinga was updated to version 1.14.0

  - the classic-UI was vulnerable to a cross site scripting attack
  (CVE-2015-8010, boo#952777)

  - A user with nagios privileges could have gained root privileges by
  placing a symbolic link at the logfile location (CVE-2016-9566,
  boo#1014637)" );
	script_tag( name: "affected", value: "icinga on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:0146-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "icinga", rpm: "icinga~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-debuginfo", rpm: "icinga-debuginfo~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-debugsource", rpm: "icinga-debugsource~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-devel", rpm: "icinga-devel~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-doc", rpm: "icinga-doc~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-idoutils", rpm: "icinga-idoutils~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-idoutils-debuginfo", rpm: "icinga-idoutils-debuginfo~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-idoutils-mysql", rpm: "icinga-idoutils-mysql~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-idoutils-oracle", rpm: "icinga-idoutils-oracle~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-idoutils-pgsql", rpm: "icinga-idoutils-pgsql~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-plugins-downtimes", rpm: "icinga-plugins-downtimes~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-plugins-eventhandlers", rpm: "icinga-plugins-eventhandlers~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-www", rpm: "icinga-www~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-www-config", rpm: "icinga-www-config~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icinga-www-debuginfo", rpm: "icinga-www-debuginfo~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "monitoring-tools", rpm: "monitoring-tools~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "monitoring-tools-debuginfo", rpm: "monitoring-tools-debuginfo~1.14.0~3.1", rls: "openSUSELeap42.1" ) )){
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

