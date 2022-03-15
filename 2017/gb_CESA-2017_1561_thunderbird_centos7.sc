if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882740" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-22 07:11:53 +0200 (Thu, 22 Jun 2017)" );
	script_cve_id( "CVE-2017-5470", "CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751", "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7756", "CVE-2017-7757", "CVE-2017-7758", "CVE-2017-7764", "CVE-2017-7771", "CVE-2017-7772", "CVE-2017-7773", "CVE-2017-7774", "CVE-2017-7775", "CVE-2017-7776", "CVE-2017-7777", "CVE-2017-7778" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-03 14:16:00 +0000 (Fri, 03 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for thunderbird CESA-2017:1561 centos7" );
	script_tag( name: "summary", value: "Check the version of thunderbird" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and
newsgroup client.

This update upgrades Thunderbird to version 52.2.0.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2017-5470, CVE-2017-5472, CVE-2017-7749, CVE-2017-7750,
CVE-2017-7751, CVE-2017-7756, CVE-2017-7771, CVE-2017-7772, CVE-2017-7773,
CVE-2017-7774, CVE-2017-7775, CVE-2017-7776, CVE-2017-7777, CVE-2017-7778,
CVE-2017-7752, CVE-2017-7754, CVE-2017-7757, CVE-2017-7758, CVE-2017-7764)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Nils, Nicolas Trippar (Zimperium zLabs), Tyson Smith,
Mats Palmgren, Philipp, Masayuki Nakano, Christian Holler, Andrew
McCreight, Gary Kwong, Andre Bargull, Carsten Book, Jesse Schwartzentruber,
Julian Hector, Marcia Knous, Ronald Crane, Samuel Erb, Holger Fuhrmannek,
Abhishek Arya, and F. Alonso (revskills) as the original reporters." );
	script_tag( name: "affected", value: "thunderbird on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:1561" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-June/022466.html" );
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
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~52.2.0~1.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

