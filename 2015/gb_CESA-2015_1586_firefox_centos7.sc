if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882243" );
	script_version( "$Revision: 14058 $" );
	script_cve_id( "CVE-2015-4473", "CVE-2015-4475", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4480", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4491", "CVE-2015-4492", "CVE-2015-4493" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-12 05:07:48 +0200 (Wed, 12 Aug 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for firefox CESA-2015:1586 centos7" );
	script_tag( name: "summary", value: "Check the version of firefox" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web
  browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2015-4473, CVE-2015-4475, CVE-2015-4478, CVE-2015-4479,
CVE-2015-4480, CVE-2015-4493, CVE-2015-4484, CVE-2015-4491, CVE-2015-4485,
CVE-2015-4486, CVE-2015-4487, CVE-2015-4488, CVE-2015-4489, CVE-2015-4492)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Gary Kwong, Christian Holler, Byron Campen, Aki
Helin, Andre Bargull, Massimiliano Tomassoli, laf.intel, Massimiliano
Tomassoli, Tyson Smith, Jukka Jylanki, Gustavo Grieco, Abhishek Arya,
Ronald Crane, and Looben Yang as the original reporters of these issues.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 38.2 ESR, which corrects these issues. After installing the
update, Firefox must be restarted for the changes to take effect." );
	script_tag( name: "affected", value: "firefox on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1586" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-August/021305.html" );
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
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~38.2.0~4.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

