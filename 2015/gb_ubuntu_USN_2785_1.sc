if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842512" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-05 06:17:24 +0100 (Thu, 05 Nov 2015)" );
	script_cve_id( "CVE-2015-4513", "CVE-2015-4514", "CVE-2015-4515", "CVE-2015-4518", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7187", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7194", "CVE-2015-7195", "CVE-2015-7196", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for firefox USN-2785-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Christian Holler, David Major, Jesse Ruderman,
Tyson Smith, Boris Zbarsky, Randell Jesup, Olli Pettay, Karl Tomlinson, Jeff Walden,
Gary Kwong, Andrew McCreight, Georg Fritzsche, and Carsten Book discovered multiple
memory safety issues in Firefox. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these to
cause a denial of service via application crash, or execute arbitrary
code with the privileges of the user invoking Firefox. (CVE-2015-4513,
CVE-2015-4514)

Tim Brown discovered that Firefox discloses the hostname during NTLM
authentication in some circumstances. If a user were tricked in to
opening a specially crafted website with NTLM v1 enabled, an attacker
could exploit this to obtain sensitive information. (CVE-2015-4515)

Mario Heiderich and Frederik Braun discovered that CSP could be bypassed
in reader mode in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit this to
conduct cross-site scripting (XSS) attacks. (CVE-2015-4518)

Tyson Smith and David Keeler discovered a use-after-poison and buffer
overflow in NSS. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-7181, CVE-2015-7182)

Ryan Sleevi discovered an integer overflow in NSPR. If a user were tricked
in to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2015-7183)

Jason Hamilton, Peter Arremann and Sylvain Giroux discovered that panels
created via the Addon SDK with { script: false } could still execute
inline script. If a user installed an addon that relied on this as a
security mechanism, an attacker could potentially exploit this to conduct
cross-site scripting (XSS) attacks, depending on the source of the panel
content. (CVE-2015-7187)

Micha&#322  Bentkowski discovered that adding white-space to hostnames that are
IP address can bypass same-origin protections. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to conduct cross-site scripting (XSS) attacks.
(CVE-2015-7188)

Looben Yang discovered a buffer overflow during script interactions with
the canvas element in some circumstances. If a user were tricked in to
opening a s ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "firefox on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2785-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2785-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|12\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "firefox", ver: "42.0+build2-0ubuntu0.15.04.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "42.0+build2-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "42.0+build2-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "42.0+build2-0ubuntu0.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

