if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877672" );
	script_version( "2021-07-19T02:00:45+0000" );
	script_cve_id( "CVE-2019-17570" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-19 02:00:45 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-16 19:15:00 +0000 (Wed, 16 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-04-07 03:20:28 +0000 (Tue, 07 Apr 2020)" );
	script_name( "Fedora: Security Advisory for xmlrpc (FEDORA-2020-1d0635bd71)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-1d0635bd71" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/I3QCRLJYQRGVTIYF4BXYRFSF3ONP3TBF" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xmlrpc'
  package(s) announced via the FEDORA-2020-1d0635bd71 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Apache XML-RPC is a Java implementation of XML-RPC, a popular protocol
that uses XML over HTTP to implement remote procedure calls." );
	script_tag( name: "affected", value: "'xmlrpc' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "xmlrpc", rpm: "xmlrpc~3.1.3~24.fc32", rls: "FC32" ) )){
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

