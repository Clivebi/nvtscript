if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882187" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-09 11:03:40 +0200 (Tue, 09 Jun 2015)" );
	script_cve_id( "CVE-2015-0797", "CVE-2015-2708", "CVE-2015-2710", "CVE-2015-2713", "CVE-2015-2716" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for firefox CESA-2015:0988 centos7" );
	script_tag( name: "summary", value: "Check the version of firefox" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2015-2708, CVE-2015-0797, CVE-2015-2710, CVE-2015-2713)

A heap-based buffer overflow flaw was found in the way Firefox processed
compressed XML data. An attacker could create specially crafted compressed
XML content that, when processed by Firefox, could cause it to crash or
execute arbitrary code with the privileges of the user running Firefox.
(CVE-2015-2716)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Jesse Ruderman, Mats Palmgren, Byron Campen, Steve
Fink, Aki Helin, Atte Kettunen, Scott Bell, and Ucha Gobejishvili as the
original reporters of these issues.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 38.0 ESR, which corrects these issues. After installing the
update, Firefox must be restarted for the changes to take effect." );
	script_tag( name: "affected", value: "firefox on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:0988" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-May/021132.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~38.0~3.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

