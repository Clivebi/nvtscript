if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842419" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-21 07:49:10 +0200 (Fri, 21 Aug 2015)" );
	script_cve_id( "CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4477", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4480", "CVE-2015-4493", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4490", "CVE-2015-4491", "CVE-2015-4492" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for firefox USN-2702-3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2702-1 fixed vulnerabilities in Firefox.
After upgrading, some users in the US reported that their default search engine
switched to Yahoo. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

Gary Kwong, Christian Holler, Byron Campen, Tyson Smith, Bobby Holley,
Chris Coulson, and Eric Rahm discovered multiple memory safety issues in
Firefox. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2015-4473, CVE-2015-4474)

Aki Helin discovered an out-of-bounds read when playing malformed MP3
content in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
obtain sensitive information, cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-4475)

A use-after-free was discovered during MediaStream playback in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-4477)

Andr&#233  Bargull discovered that non-configurable properties on javascript
objects could be redefined when parsing JSON. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to bypass same-origin restrictions. (CVE-2015-4478)

Multiple integer overflows were discovered in libstagefright. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-4479, CVE-2015-4480, CVE-2015-4493)

Jukka Jyl&#228 nki discovered a crash that occurs because javascript does not
properly gate access to Atomics or SharedArrayBuffers in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service. (CVE-2015-4484)

Abhishek Arya discovered 2 buffer overflows in libvpx when decoding
malformed WebM content in some circumstances. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit these to cause a denial of service via application crash, or
execute ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "firefox on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2702-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2702-3/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "40.0+build4-0ubuntu0.14.04.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "40.0+build4-0ubuntu0.12.04.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

