if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882592" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-20 05:36:58 +0100 (Sun, 20 Nov 2016)" );
	script_cve_id( "CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-9064", "CVE-2016-9066" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for firefox CESA-2016:2780 centos6" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 45.5.0 ESR.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2016-5296, CVE-2016-5297, CVE-2016-9066, CVE-2016-5291,
CVE-2016-5290)

  * A flaw was found in the way Add-on update process was handled by Firefox.
A Man-in-the-Middle attacker could use this flaw to install a malicious
signed add-on update. (CVE-2016-9064)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Abhishek Arya, Andre Bargull, Samuel Grob, Yuyang
Zhou, Olli Pettay, Christian Holler, Ehsan Akhgari, Jon Coppeard, Gary
Kwong, Tooru Fujisawa, Philipp, and Randell Jesup as the original
reporters." );
	script_tag( name: "affected", value: "firefox on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:2780" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-November/022156.html" );
	script_tag( name: "summary", value: "Check for the Version of firefox" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~45.5.0~1.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

