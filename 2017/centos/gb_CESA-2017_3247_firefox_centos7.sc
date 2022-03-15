if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882802" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-18 07:32:40 +0100 (Sat, 18 Nov 2017)" );
	script_cve_id( "CVE-2017-7826", "CVE-2017-7828", "CVE-2017-7830" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-01 12:06:00 +0000 (Wed, 01 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for firefox CESA-2017:3247 centos7" );
	script_tag( name: "summary", value: "Check the version of firefox" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 52.5.0 ESR.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2017-7826, CVE-2017-7828, CVE-2017-7830)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Christian Holler, David Keeler, Jon Coppeard, Julien
Cristau, Jan de Mooij, Jason Kratzer, Philipp, Nicholas Nethercote, Oriol
Brufau, Andre Bargull, Bob Clary, Jet Villegas, Randell Jesup, Tyson Smith,
Gary Kwong, Ryan VanderMeulen, Nils, and Jun Kokatsu as the original
reporters." );
	script_tag( name: "affected", value: "firefox on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:3247" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-November/022628.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~52.5.0~1.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

