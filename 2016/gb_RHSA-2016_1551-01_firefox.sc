if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871646" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-08-04 16:27:25 +0530 (Thu, 04 Aug 2016)" );
	script_cve_id( "CVE-2016-2830", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for firefox RHSA-2016:1551-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 45.3.0 ESR.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2016-2836, CVE-2016-5258, CVE-2016-5259, CVE-2016-5252,
CVE-2016-5263, CVE-2016-2830, CVE-2016-2838, CVE-2016-5254, CVE-2016-5262,
CVE-2016-5264, CVE-2016-5265, CVE-2016-2837)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Looben Yang, Carsten Book, Christian Holler, Gary
Kwong, Jesse Ruderman, Andrew McCreight, Phil Ringnalda, Philipp, Toni
Huttunen, Georg Koppen, Abhishek Arya, Atte Kettunen, Nils, Nikita Arykov,
and Abdulrahman Alqabandi as the original reporters." );
	script_tag( name: "affected", value: "firefox on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:1551-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-August/msg00006.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(7|6|5)" );
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
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~45.3.0~1.el7_2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "firefox-debuginfo", rpm: "firefox-debuginfo~45.3.0~1.el7_2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~45.3.0~1.el6_8", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "firefox-debuginfo", rpm: "firefox-debuginfo~45.3.0~1.el6_8", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~45.3.0~1.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "firefox-debuginfo", rpm: "firefox-debuginfo~45.3.0~1.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

