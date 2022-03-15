if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842476" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-06 12:42:54 +0200 (Tue, 06 Oct 2015)" );
	script_cve_id( "CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4502", "CVE-2015-4504", "CVE-2015-4506", "CVE-2015-4507", "CVE-2015-4508", "CVE-2015-4509", "CVE-2015-4510", "CVE-2015-4512", "CVE-2015-4516", "CVE-2015-4517", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180", "CVE-2015-4519", "CVE-2015-4520" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for firefox USN-2743-4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2743-1 fixed vulnerabilities in Firefox.
After upgrading, some users reported problems with bookmark creation and crashes
in some circumstances. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

Andrew Osmond, Olli Pettay, Andrew Sutherland, Christian Holler, David
Major, Andrew McCreight, Cameron McCormack, Bob Clary and Randell Jesup
discovered multiple memory safety issues in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-4500, CVE-2015-4501)

Andr&#233  Bargull discovered that when a web page creates a scripted proxy
for the window with a handler defined a certain way, a reference to the
inner window will be passed, rather than that of the outer window.
(CVE-2015-4502)

Felix Gr&#246 bert discovered an out-of-bounds read in the QCMS color
management library in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via application crash, or obtain
sensitive information. (CVE-2015-4504)

Khalil Zhani discovered a buffer overflow when parsing VP9 content in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-4506)

Spandan Veggalam discovered a crash while using the debugger API in some
circumstances. If a user were tricked in to opening a specially crafted
website whilst using the debugger, an attacker could potentially exploit
this to execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-4507)

Juho Nurminen discovered that the URL bar could display the wrong URL in
reader mode in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
conduct URL spoofing attacks. (CVE-2015-4508)

A use-after-free was discovered when manipulating HTML media content in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2015-4509)

Looben Yang discovered a use-after-free when using a shar ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "firefox on Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2743-4" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2743-4/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|12\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.04"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "41.0.1+build2-0ubuntu0.15.04.2", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "41.0.1+build2-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "41.0.1+build2-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
