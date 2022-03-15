if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878945" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2021-26925" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-19 17:38:00 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-18 04:02:51 +0000 (Thu, 18 Feb 2021)" );
	script_name( "Fedora: Security Advisory for roundcubemail (FEDORA-2021-aef54ec149)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-aef54ec149" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5QPAMYM2DQODSCQIAVNFJR2ETG7WMJOD" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'roundcubemail'
  package(s) announced via the FEDORA-2021-aef54ec149 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "RoundCube Webmail is a browser-based multilingual IMAP client
with an application-like user interface. It provides full
functionality you expect from an e-mail client, including MIME
support, address book, folder manipulation, message searching
and spell checking. RoundCube Webmail is written in PHP and
requires a database: MySQL, PostgreSQL and SQLite are known to
work. The user interface is fully skinnable using XHTML and
CSS 2." );
	script_tag( name: "affected", value: "'roundcubemail' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "roundcubemail", rpm: "roundcubemail~1.4.11~1.fc32", rls: "FC32" ) )){
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

