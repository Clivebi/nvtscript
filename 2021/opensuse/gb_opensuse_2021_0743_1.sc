if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853814" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2016-3822", "CVE-2018-16554", "CVE-2018-17088", "CVE-2018-6612", "CVE-2019-1010301", "CVE-2019-1010302", "CVE-2020-6624", "CVE-2020-6625", "CVE-2021-3496" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-05 20:33:00 +0000 (Mon, 05 Nov 2018)" );
	script_tag( name: "creation_date", value: "2021-05-17 03:01:07 +0000 (Mon, 17 May 2021)" );
	script_name( "openSUSE: Security Advisory for jhead (openSUSE-SU-2021:0743-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0743-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JPTEPBJVJFSKKHSTZER2JVIMRP7MGN2C" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jhead'
  package(s) announced via the openSUSE-SU-2021:0743-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for jhead fixes the following issues:

     jhead was updated to 3.06.0.1

  * lot of fuzztest fixes

  * Apply a whole bunch of patches from Debian.

  * Spell check and fuzz test stuff from Debian, nothing useful to human
       users.

  * Add option to set exif date from date from another file.

  * Bug fixes relating to fuzz testing.

  * Fix bug where thumbnail replacement DID NOT WORK.

  * Fix bug when no orientation tag is present

  * Fix bug of not clearing exif information when processing images with an
       without exif data in one invocation.

  * Remove some unnecessary warnings with some types of GPS data

  * Remove multiple copies of the same type of section when deleting section
       types" );
	script_tag( name: "affected", value: "'jhead' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "jhead", rpm: "jhead~3.06.0.1~lp152.7.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jhead-debuginfo", rpm: "jhead-debuginfo~3.06.0.1~lp152.7.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jhead-debugsource", rpm: "jhead-debugsource~3.06.0.1~lp152.7.6.1", rls: "openSUSELeap15.2" ) )){
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

