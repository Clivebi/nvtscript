if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877912" );
	script_version( "2021-07-19T11:00:51+0000" );
	script_cve_id( "CVE-2015-8854", "CVE-2016-1000013", "CVE-2017-17461", "CVE-2017-1000427" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-19 11:00:51 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-31 06:15:00 +0000 (Sun, 31 May 2020)" );
	script_tag( name: "creation_date", value: "2020-06-07 03:27:41 +0000 (Sun, 07 Jun 2020)" );
	script_name( "Fedora: Security Advisory for marked (FEDORA-2020-5eca570e16)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-5eca570e16" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M6BJG6RGDH7ZWVVAUFBFI5L32RSMQN2S" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'marked'
  package(s) announced via the FEDORA-2020-5eca570e16 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Install this for command line tool and man page.

marked is a full-featured markdown compiler that can parse huge chunks of
markdown without having to worry about caching the compiled output or
blocking for an unnecessarily long time.

marked is extremely fast and frequently outperforms similar markdown parsers.
marked is very concise and still implements all markdown features, as well
as GitHub Flavored Markdown features.

marked more or less passes the official markdown test suite in its entirety.
This is important because a surprising number of markdown compilers cannot
pass more than a few tests." );
	script_tag( name: "affected", value: "'marked' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "marked", rpm: "marked~1.1.0~3.fc31", rls: "FC31" ) )){
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

