if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851979" );
	script_version( "2021-06-29T11:00:37+0000" );
	script_cve_id( "CVE-2017-18266" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-14 13:33:00 +0000 (Thu, 14 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:26:22 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for xdg-utils (openSUSE-SU-2018:1596-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:1596-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-06/msg00009.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xdg-utils'
  package(s) announced via the openSUSE-SU-2018:1596-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xdg-utils fixes this security issues:

  - CVE-2017-18266: The open_envvar function in xdg-open did not validate
  strings launching the program specified by the BROWSER environment
  variable, which might allowed remote attackers to conduct
  argument-injection attacks via a crafted URL (bsc#1093086).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-573=1" );
	script_tag( name: "affected", value: "xdg-utils on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "xdg-utils", rpm: "xdg-utils~20170508~lp150.3.3.2", rls: "openSUSELeap15.0" ) )){
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

