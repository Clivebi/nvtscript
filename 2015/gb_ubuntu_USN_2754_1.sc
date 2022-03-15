if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842482" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-06 12:43:29 +0200 (Tue, 06 Oct 2015)" );
	script_cve_id( "CVE-2015-4500", "CVE-2015-4506", "CVE-2015-4509", "CVE-2015-4511", "CVE-2015-4517", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180", "CVE-2015-4519", "CVE-2015-4520" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for thunderbird USN-2754-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Andrew Osmond, Olli Pettay, Andrew
Sutherland, Christian Holler, David Major, Andrew McCreight, and Cameron
McCormack discovered multiple memory safety issues in Thunderbird. If a user were
tricked in to opening a specially crafted message, an attacker could potentially
exploit these to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Thunderbird. (CVE-2015-4500)

Khalil Zhani discovered a buffer overflow when parsing VP9 content in some
circumstances. If a user were tricked in to opening a specially crafted
message, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Thunderbird. (CVE-2015-4506)

A use-after-free was discovered when manipulating HTML media content in
some circumstances. If a user were tricked in to opening a specially
crafted website in a browsing context, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2015-4509)

Atte Kettunen discovered a buffer overflow in the nestegg library when
decoding WebM format video in some circumstances. If a user were tricked
in to opening a specially crafted message, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2015-4511)

Ronald Crane reported multiple vulnerabilities. If a user were tricked in
to opening a specially crafted website in a browsing context, an attacker
could potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Thunderbird. (CVE-2015-4517, CVE-2015-4521, CVE-2015-4522,
CVE-2015-7174, CVE-2015-7175, CVE-2015-7176, CVE-2015-7177, CVE-2015-7180)

Mario Gomes discovered that dragging and dropping an image after a
redirect exposes the redirected URL to scripts. An attacker could
potentially exploit this to obtain sensitive information. (CVE-2015-4519)

Ehsan Akhgari discovered 2 issues with CORS preflight requests. An
attacker could potentially exploit these to bypass CORS restrictions.
(CVE-2015-4520)" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2754-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2754-1/" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.3.0+build1-0ubuntu0.15.04.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.3.0+build1-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.3.0+build1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

