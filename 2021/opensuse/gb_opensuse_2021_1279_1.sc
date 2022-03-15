if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854169" );
	script_version( "2021-09-22T08:01:20+0000" );
	script_cve_id( "CVE-2021-29133" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 08:01:20 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 20:53:00 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-09-17 01:03:57 +0000 (Fri, 17 Sep 2021)" );
	script_name( "openSUSE: Security Advisory for haserl (openSUSE-SU-2021:1279-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1279-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JVYZKN3OCXW2QGY6YJEPECSXP6JIERGL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'haserl'
  package(s) announced via the openSUSE-SU-2021:1279-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for haserl fixes the following issues:

     Update to version 0.9.36:

  * Fixed: Its possible to issue a PUT request without a CONTENT-TYPE.
       Assume an octet-stream in that case. This is CVE-2021-29133 and
       boo#1187671

  * Change the Prefix for variables to be the REQUEST_METHOD
       (PUT/DELETE/GET/POST) THIS IS A BREAKING CHANGE

  * Mitigations vs running haserl to get access to files not available to
       the user." );
	script_tag( name: "affected", value: "'haserl' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "haserl", rpm: "haserl~0.9.36~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "haserl-debuginfo", rpm: "haserl-debuginfo~0.9.36~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "haserl-debugsource", rpm: "haserl-debugsource~0.9.36~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
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

