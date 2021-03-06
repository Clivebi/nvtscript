if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842784" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-06-10 05:23:14 +0200 (Fri, 10 Jun 2016)" );
	script_cve_id( "CVE-2016-3947", "CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for squid3 USN-2995-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid3'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Yuriy M. Kaminskiy discovered that the Squid pinger utility incorrectly
handled certain ICMPv6 packets. A remote attacker could use this issue to
cause Squid to crash, resulting in a denial of service, or possibly cause
Squid to leak information into log files. (CVE-2016-3947)

Yuriy M. Kaminskiy discovered that the Squid cachemgr.cgi tool incorrectly
handled certain crafted data. A remote attacker could use this issue to
cause Squid to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-4051)

It was discovered that Squid incorrectly handled certain Edge Side Includes
(ESI) responses. A remote attacker could possibly use this issue to cause
Squid to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-4052, CVE-2016-4053, CVE-2016-4054)

Jianjun Chen discovered that Squid did not correctly ignore the Host header
when absolute-URI is provided. A remote attacker could possibly use this
issue to conduct cache-poisoning attacks. This issue only affected Ubuntu
14.04 LTS, Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2016-4553)

Jianjun Chen discovered that Squid incorrectly handled certain HTTP Host
headers. A remote attacker could possibly use this issue to conduct
cache-poisoning attacks. (CVE-2016-4554)

It was discovered that Squid incorrectly handled certain Edge Side Includes
(ESI) responses. A remote attacker could possibly use this issue to cause
Squid to crash, resulting in a denial of service. (CVE-2016-4555,
CVE-2016-4556)" );
	script_tag( name: "affected", value: "squid3 on Ubuntu 16.04 LTS,
  Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2995-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2995-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|16\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.3.8-1ubuntu6.8", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squid3", ver: "3.3.8-1ubuntu6.8", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.1.19-1ubuntu3.12.04.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squid3", ver: "3.1.19-1ubuntu3.12.04.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.5.12-1ubuntu7.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squid3", ver: "3.5.12-1ubuntu7.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.3.8-1ubuntu16.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "squid3", ver: "3.3.8-1ubuntu16.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

