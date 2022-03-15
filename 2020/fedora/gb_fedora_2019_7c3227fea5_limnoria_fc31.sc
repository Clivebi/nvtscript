if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877219" );
	script_version( "2021-07-16T02:00:53+0000" );
	script_cve_id( "CVE-2019-19010" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-16 02:00:53 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:32:51 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for limnoria FEDORA-2019-7c3227fea5" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-7c3227fea5" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DRNOUHFEN75QAIKT4Y3HDN3TT5LSIWN2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'limnoria'
  package(s) announced via the FEDORA-2019-7c3227fea5 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Supybot is a robust (it doesn&#39, t crash), user friendly
(it&#39, s easy to configure) and programmer friendly
(plugins are extremely easy to write) Python IRC bot.
It aims to be an adequate replacement for most existing IRC bots.
It includes a very flexible and powerful ACL system for controlling
access to commands, as well as more than 50 builtin plugins
providing around 400 actual commands.

Limnoria is a project which continues development of Supybot
(you can call it a fork) by fixing bugs and adding features
(see the list of added features for more details)." );
	script_tag( name: "affected", value: "'limnoria' package(s) on Fedora 31." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "limnoria", rpm: "limnoria~20191109~2.fc31", rls: "FC31" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

