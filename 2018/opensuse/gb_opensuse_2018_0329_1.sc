if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851695" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-01 07:53:54 +0100 (Thu, 01 Feb 2018)" );
	script_cve_id( "CVE-2016-5684" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-28 20:29:00 +0000 (Thu, 28 Mar 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for freeimage (openSUSE-SU-2018:0329-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freeimage'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for freeimage fixes one issues.

  This security issue was fixed:

  - CVE-2016-5684: Prevent out-of-bounds write vulnerability in the XMP
  image handling functionality. A specially crafted XMP file could have
  caused an arbitrary memory overwrite resulting in code execution
  (boo#1002621)." );
	script_tag( name: "affected", value: "freeimage on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:0329-1" );
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
	if(!isnull( res = isrpmvuln( pkg: "freeimage-debugsource", rpm: "freeimage-debugsource~3.17.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeimage-devel", rpm: "freeimage-devel~3.17.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreeimage3", rpm: "libfreeimage3~3.17.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreeimage3-debuginfo", rpm: "libfreeimage3-debuginfo~3.17.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreeimageplus3", rpm: "libfreeimageplus3~3.17.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreeimageplus3-debuginfo", rpm: "libfreeimageplus3-debuginfo~3.17.0~5.1", rls: "openSUSELeap42.3" ) )){
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

