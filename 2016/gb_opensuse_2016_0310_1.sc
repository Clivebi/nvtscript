if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851186" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-02-02 17:17:04 +0100 (Tue, 02 Feb 2016)" );
	script_cve_id( "CVE-2016-1930", "CVE-2016-1935" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for xulrunner (openSUSE-SU-2016:0310-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xulrunner'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "XULRunner was updated to 38.6.0 to fix two security issues.

  The following vulnerabilities were fixed:

  * CVE-2016-1930: Miscellaneous memory safety hazards (boo#963632)

  * CVE-2016-1935: Buffer overflow in WebGL after out of memory allocation
  (boo#963635)" );
	script_tag( name: "affected", value: "xulrunner on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:0310-1" );
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
	if(!isnull( res = isrpmvuln( pkg: "xulrunner", rpm: "xulrunner~38.6.0~10.2", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xulrunner-debuginfo", rpm: "xulrunner-debuginfo~38.6.0~10.2", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xulrunner-debugsource", rpm: "xulrunner-debugsource~38.6.0~10.2", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xulrunner-devel", rpm: "xulrunner-devel~38.6.0~10.2", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xulrunner-32bit", rpm: "xulrunner-32bit~38.6.0~10.2", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xulrunner-debuginfo-32bit", rpm: "xulrunner-debuginfo-32bit~38.6.0~10.2", rls: "openSUSELeap42.1" ) )){
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

