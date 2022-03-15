if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876937" );
	script_version( "2021-09-02T10:01:39+0000" );
	script_cve_id( "CVE-2017-6059", "CVE-2017-6062", "CVE-2017-6413", "CVE-2019-14857" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-30 00:15:00 +0000 (Thu, 30 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-10-26 02:27:35 +0000 (Sat, 26 Oct 2019)" );
	script_name( "Fedora Update for mod_auth_openidc FEDORA-2019-7b06f18a10" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-7b06f18a10" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EJXBG3DG2FUYFGTUTSJFMPIINVFKKB4Z" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mod_auth_openidc'
  package(s) announced via the FEDORA-2019-7b06f18a10 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This module enables an Apache 2.x web server to operate as
an OpenID Connect Relying Party and/or OAuth 2.0 Resource Server." );
	script_tag( name: "affected", value: "'mod_auth_openidc' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "mod_auth_openidc", rpm: "mod_auth_openidc~2.4.0.3~1.fc30", rls: "FC30" ) )){
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

