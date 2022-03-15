if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851851" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-14 05:56:27 +0200 (Tue, 14 Aug 2018)" );
	script_cve_id( "CVE-2018-13796" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-06 20:15:00 +0000 (Wed, 06 May 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for mailman (openSUSE-SU-2018:2309-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mailman'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mailman fixes the following issues:

  Security issue fixed:

  - CVE-2018-13796: Fix a content spoofing vulnerability with invalid list
  name messages inside the web UI (boo#1101288).

  Bug fixes:

  - update to 2.1.29:

  * Fixed the listinfo and admin overview pages that were broken

  - update to 2.1.28:

  * It is now possible to edit HTML and text templates via the web admin
  UI in a supported language other than the list's preferred_language.

  * The Japanese translation has been updated

  * The German translation has been updated

  * The Esperanto translation has been updated

  * The BLOCK_SPAMHAUS_LISTED_DBL_SUBSCRIBE feature added in 2.1.27 was
  not working.  This is fixed.

  * Escaping of HTML entities for the web UI is now done more selectively.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-861=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-861=1" );
	script_tag( name: "affected", value: "mailman on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2309-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00046.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "mailman", rpm: "mailman~2.1.29~2.11.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mailman-debuginfo", rpm: "mailman-debuginfo~2.1.29~2.11.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mailman-debugsource", rpm: "mailman-debugsource~2.1.29~2.11.2", rls: "openSUSELeap42.3" ) )){
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

