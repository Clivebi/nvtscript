if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879749" );
	script_version( "2021-08-20T06:00:57+0000" );
	script_cve_id( "CVE-2021-20718" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 06:00:57 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-11 03:15:00 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-17 03:24:44 +0000 (Thu, 17 Jun 2021)" );
	script_name( "Fedora: Security Advisory for mod_auth_openidc (FEDORA-2021-cc85f79f63)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-cc85f79f63" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FV4KYMQWPS3I2QPW2C253MLIAFGBZPLK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mod_auth_openidc'
  package(s) announced via the FEDORA-2021-cc85f79f63 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This module enables an Apache 2.x web server to operate as
an OpenID Connect Relying Party and/or OAuth 2.0 Resource Server." );
	script_tag( name: "affected", value: "'mod_auth_openidc' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "mod_auth_openidc", rpm: "mod_auth_openidc~2.4.8.4~1.fc33", rls: "FC33" ) )){
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

