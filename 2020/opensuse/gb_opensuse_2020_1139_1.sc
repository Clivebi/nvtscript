if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853334" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2020-15917" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-03 07:15:00 +0000 (Tue, 03 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-08-04 03:01:18 +0000 (Tue, 04 Aug 2020)" );
	script_name( "openSUSE: Security Advisory for claws-mail (openSUSE-SU-2020:1139-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1139-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00002.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'claws-mail'
  package(s) announced via the openSUSE-SU-2020:1139-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for claws-mail fixes the following issues:

  - Update to 3.17.6:

  * It is now possible to 'Inherit Folder properties and processing rules
  from parent folder' when creating new folders with the move message and
  copy message dialogues.

  * A Phishing warning is now shown when copying a phishing URL, (in
  addition to clicking a phishing URL).

  * The progress window when importing an mbox file is now more responsive.

  * A warning dialogue is shown if the selected privacy system is 'None'
  and automatic signing amd/or encrypting is enabled.

  * Python plugin: pkgconfig is now used to check for python2. This enables
  the Python plugin (which uses python2) to be built on newer systems
  which have both python2 and python3.

  - CVE-2020-15917: Fixed an improper handling of suffix data after STARTTLS
  is mishandled (boo#1174457).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1139=1" );
	script_tag( name: "affected", value: "'claws-mail' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "claws-mail", rpm: "claws-mail~3.17.6~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "claws-mail-debuginfo", rpm: "claws-mail-debuginfo~3.17.6~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "claws-mail-debugsource", rpm: "claws-mail-debugsource~3.17.6~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "claws-mail-devel", rpm: "claws-mail-devel~3.17.6~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "claws-mail-lang", rpm: "claws-mail-lang~3.17.6~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
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

