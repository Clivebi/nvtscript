if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851294" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-05-06 15:29:39 +0530 (Fri, 06 May 2016)" );
	script_cve_id( "CVE-2016-1601" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for yast2-users (openSUSE-SU-2016:1226-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'yast2-users'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "yast2-users was updated to fix one security issue.

  This security issue was fixed:

  - CVE-2016-1601: Empty passwords fields in /etc/shadow after SLES 12 SP1
  autoyast installation (bsc#974220).

  This update includes a script that fixes installations that we're affected
  by this problem. It is run automatically upon installing the update.

  This non-security issue was fixed:

  - bsc#971804: Set root password correctly when using a minimal profile

  This update was imported from the SUSE:SLE-12-SP1:Update update project." );
	script_tag( name: "affected", value: "yast2-users on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:1226-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(!isnull( res = isrpmvuln( pkg: "yast2-users", rpm: "yast2-users~3.1.41.3~10.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "yast2-users-debuginfo", rpm: "yast2-users-debuginfo~3.1.41.3~10.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "yast2-users-debugsource", rpm: "yast2-users-debugsource~3.1.41.3~10.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "yast2-users-devel-doc", rpm: "yast2-users-devel-doc~3.1.41.3~10.1", rls: "openSUSELeap42.1" ) )){
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

