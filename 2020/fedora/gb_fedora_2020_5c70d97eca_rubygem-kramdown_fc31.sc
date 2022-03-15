if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878209" );
	script_version( "2021-07-14T02:00:49+0000" );
	script_cve_id( "CVE-2020-14001" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-14 02:00:49 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-06 16:15:00 +0000 (Tue, 06 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-08-20 03:08:40 +0000 (Thu, 20 Aug 2020)" );
	script_name( "Fedora: Security Advisory for rubygem-kramdown (FEDORA-2020-5c70d97eca)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-5c70d97eca" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ENMMGKHRQIZ3QKGOMBBBGB6B4LB5I7NQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-kramdown'
  package(s) announced via the FEDORA-2020-5c70d97eca advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "kramdown is yet-another-markdown-parser but fast, pure Ruby,
using a strict syntax definition and supporting several common extensions." );
	script_tag( name: "affected", value: "'rubygem-kramdown' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "rubygem-kramdown", rpm: "rubygem-kramdown~1.17.0~6.fc31", rls: "FC31" ) )){
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

