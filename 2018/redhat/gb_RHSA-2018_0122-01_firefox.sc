if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.910005" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-25 07:52:56 +0100 (Thu, 25 Jan 2018)" );
	script_cve_id( "CVE-2018-5089", "CVE-2018-5091", "CVE-2018-5095", "CVE-2018-5096", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104", "CVE-2018-5117" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-03 16:53:00 +0000 (Fri, 03 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for firefox RHSA-2018:0122-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 52.6.0 ESR.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2018-5089, CVE-2018-5091, CVE-2018-5095, CVE-2018-5096,
CVE-2018-5097, CVE-2018-5098, CVE-2018-5099, CVE-2018-5102, CVE-2018-5103,
CVE-2018-5104, CVE-2018-5117)

  * To mitigate timing-based side-channel attacks similar to 'Spectre' and
'Meltdown', the resolution of performance.now() has been reduced from 5s
to 20s.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Christian Holler, Jason Kratzer, Marcia Knous, Nathan
Froyd, Oriol Brufau, Ronald Crane, Randell Jesup, Tyson Smith, Cobos
lvarez, Ryan VanderMeulen, Sebastian Hengst, Karl Tomlinson, Xidorn Quan,
Ludovic Hirlimann, Jason Orendorff, Looben Yang, Anonymous, Nils, and
Xisigr as the original reporters." );
	script_tag( name: "affected", value: "firefox on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2018:0122-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2018-January/msg00078.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(7|6)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~52.6.0~1.el7_4", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "firefox-debuginfo", rpm: "firefox-debuginfo~52.6.0~1.el7_4", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~52.6.0~1.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "firefox-debuginfo", rpm: "firefox-debuginfo~52.6.0~1.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

