if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852377" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2019-9894", "CVE-2019-9895", "CVE-2019-9896", "CVE-2019-9897", "CVE-2019-9898" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-05 05:29:00 +0000 (Fri, 05 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-04-03 06:42:01 +0000 (Wed, 03 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for putty (openSUSE-SU-2019:1113-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1113-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00004.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'putty'
  package(s) announced via the openSUSE-SU-2019:1113-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for putty fixes the following issues:

  Update to new upstream release 0.71 [boo#1129633]

  * CVE-2019-9894: Fixed a remotely triggerable memory overwrite in RSA key
  exchange, which can occur before host key verification potential
  recycling of random numbers used in cryptography.

  * CVE-2019-9895: Fixed a remotely triggerable buffer overflow in any kind
  of server-to-client forwarding.

  * CVE-2019-9897: Fixed multiple denial-of-service attacks that can be
  triggered by writing to the terminal.

  * CVE-2019-9898: Fixed potential recycling of random numbers used in
  cryptography

  * CVE-2019-9896 (Windows only): Fixed hijacking by a malicious help file
  in the same directory as the executable

  * Major rewrite of the crypto code to remove cache and timing side
  channels.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1113=1" );
	script_tag( name: "affected", value: "'putty' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "putty", rpm: "putty~0.71~lp150.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "putty-debuginfo", rpm: "putty-debuginfo~0.71~lp150.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "putty-debugsource", rpm: "putty-debugsource~0.71~lp150.9.1", rls: "openSUSELeap15.0" ) )){
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

