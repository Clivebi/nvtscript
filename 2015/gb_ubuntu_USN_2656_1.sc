if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842279" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-10 06:09:51 +0200 (Fri, 10 Jul 2015)" );
	script_cve_id( "CVE-2015-2721", "CVE-2015-2722", "CVE-2015-2733", "CVE-2015-2724", "CVE-2015-2725", "CVE-2015-2726", "CVE-2015-2727", "CVE-2015-2728", "CVE-2015-2729", "CVE-2015-2730", "CVE-2015-2731", "CVE-2015-2734", "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739", "CVE-2015-2740", "CVE-2015-2741", "CVE-2015-2743", "CVE-2015-4000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for firefox USN-2656-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Karthikeyan Bhargavan discovered that NSS
incorrectly handled state transitions for the TLS state machine. If a remote attacker
were able to perform a man-in-the-middle attack, this flaw could be exploited to skip
the ServerKeyExchange message and remove the forward-secrecy property.
(CVE-2015-2721)

Looben Yan discovered 2 use-after-free issues when using XMLHttpRequest in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2015-2722,
CVE-2015-2733)

Bob Clary, Christian Holler, Bobby Holley, Andrew McCreight, Terrence
Cole, Steve Fink, Mats Palmgren, Wes Kocher, Andreas Pehrson, Tooru
Fujisawa, Andrew Sutherland, and Gary Kwong discovered multiple memory
safety issues in Firefox. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2015-2724,
CVE-2015-2725, CVE-2015-2726)

Armin Razmdjou discovered that opening hyperlinks with specific mouse
and key combinations could allow a Chrome privileged URL to be opened
without context restrictions being preserved. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to bypass security restrictions. (CVE-2015-2727)

Paul Bandha discovered a type confusion bug in the Indexed DB Manager. If
a user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2015-2728)

Holger Fuhrmannek discovered an out-of-bounds read in Web Audio. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to obtain sensitive information.
(CVE-2015-2729)

Watson Ladd discovered that NSS incorrectly handled Elliptical Curve
Cryptography (ECC) multiplication. A remote attacker could possibly use
this issue to spoof ECDSA signatures. (CVE-2015-2730)

A use-after-free was discovered when a Content Policy modifies the DOM to
remove a DOM object. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-2 ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "firefox on Ubuntu 14.10,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2656-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2656-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "39.0+build5-0ubuntu0.14.10.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "39.0+build5-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

